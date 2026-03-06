/**
 * main.cpp - SSH Log Parser (C++ Service)
 *
 * High-performance SSH authentication log parser that:
 *   1. Tails SSH auth logs (/var/log/auth.log on Linux, /var/log/system.log on macOS)
 *   2. Identifies failed and successful SSH login attempts via regex.
 *   3. Maintains per-IP failure counts in an unordered_map (O(1) avg).
 *   4. Aggregates failures per minute using time-bucket keys.
 *   5. Writes a structured JSON summary to a shared file every second.
 *
 * The JSON file is consumed by the Python Prometheus exporter.
 *
 * Build:
 *   mkdir build && cd build && cmake .. && make
 *
 * Run (auto-detects OS):
 *   ./ssh_parser [--log /var/log/auth.log] [--out /shared/ssh_metrics.json]
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <regex>
#include <chrono>
#include <thread>
#include <ctime>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <atomic>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// ─── OS Detection ────────────────────────────────────────────────────────────

/**
 * Returns the platform-appropriate default SSH auth log path.
 * - Linux (Ubuntu/Debian): /var/log/auth.log
 * - macOS: /var/log/system.log
 */
std::string get_default_log_path() {
    struct utsname buf;
    if (uname(&buf) == 0) {
        std::string sysname(buf.sysname);
        if (sysname == "Darwin") {
            // macOS uses system.log for syslog messages
            return "/var/log/system.log";
        }
    }
    // Default to Linux auth.log
    return "/var/log/auth.log";
}

// ─── Configuration ───────────────────────────────────────────────────────────

static const std::string DEFAULT_LOG_PATH = get_default_log_path();
static const std::string DEFAULT_OUT_PATH = "/shared/ssh_metrics.json";
static const int         REPORT_INTERVAL  = 1;  // seconds

// ─── Global State ────────────────────────────────────────────────────────────

static std::atomic<bool> g_running{true};

// Counters
static int total_failures  = 0;
static int total_successes = 0;

// Per-IP failure counter   – O(1) average insert / lookup
static std::unordered_map<std::string, int> failures_per_ip;

// Time-bucket failure counter  – key is (epoch / 60)
static std::unordered_map<long, int> failures_per_minute;

static std::mutex state_mutex;

// ─── Signal Handler ──────────────────────────────────────────────────────────

void signal_handler(int) { g_running.store(false); }

// ─── Parsing Helpers ─────────────────────────────────────────────────────────

/**
 * Extract an IPv4 address from a log line.
 * Returns empty string if no IP found.
 */
std::string extract_ip(const std::string& line) {
    // Simple IPv4 regex – sufficient for auth.log
    static const std::regex ip_re(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    std::smatch match;
    if (std::regex_search(line, match, ip_re)) {
        return match[1].str();
    }
    return "";
}

/**
 * Extract the target username from "for <user>" or "user <user>".
 */
std::string extract_username(const std::string& line) {
    static const std::regex user_re(R"((?:for|user)\s+(\w+))");
    std::smatch match;
    if (std::regex_search(line, match, user_re)) {
        return match[1].str();
    }
    return "unknown";
}

/**
 * Determine if the line is an SSH authentication event.
 * Sets `is_failure` accordingly.
 * Returns true if the line is relevant, false otherwise.
 */
bool is_ssh_event(const std::string& line, bool& is_failure) {
    // Failed password / Invalid user → failure
    if (line.find("Failed password") != std::string::npos ||
        line.find("Invalid user")    != std::string::npos ||
        line.find("authentication failure") != std::string::npos) {
        is_failure = true;
        return true;
    }
    // Accepted password / publickey → success
    if (line.find("Accepted password")  != std::string::npos ||
        line.find("Accepted publickey") != std::string::npos) {
        is_failure = false;
        return true;
    }
    return false;
}

// ─── State Update ────────────────────────────────────────────────────────────

void record_event(bool is_failure, const std::string& ip) {
    std::lock_guard<std::mutex> lock(state_mutex);

    if (is_failure) {
        total_failures++;
        if (!ip.empty()) {
            failures_per_ip[ip]++;          // O(1) amortised
        }
        // Bucket by minute: key = current epoch / 60
        long bucket = static_cast<long>(std::time(nullptr)) / 60;
        failures_per_minute[bucket]++;
    } else {
        total_successes++;
    }
}

// ─── JSON Builder ────────────────────────────────────────────────────────────

/**
 * Compute failures that occurred within the last 60 seconds.
 * Scans at most a handful of minute-buckets (usually 1–2).
 */
int compute_failures_last_minute() {
    long now_bucket  = static_cast<long>(std::time(nullptr)) / 60;
    long prev_bucket = now_bucket - 1;
    int  count = 0;
    auto it1 = failures_per_minute.find(now_bucket);
    if (it1 != failures_per_minute.end()) count += it1->second;
    auto it2 = failures_per_minute.find(prev_bucket);
    if (it2 != failures_per_minute.end()) count += it2->second;
    return count;
}

/**
 * Build a JSON string with the current metrics snapshot.
 * Example output:
 * {
 *   "epoch": 1700000000,
 *   "total_failures": 42,
 *   "total_successes": 10,
 *   "failures_last_minute": 8,
 *   "failures_per_ip": { "192.168.1.100": 15, ... },
 *   "top_ips": [ {"ip": "...", "count": N}, ... ]
 * }
 */
std::string build_json() {
    std::lock_guard<std::mutex> lock(state_mutex);

    long epoch = static_cast<long>(std::time(nullptr));
    int  flm   = compute_failures_last_minute();

    // Sort IPs by failure count descending → pick top 10
    std::vector<std::pair<std::string, int>> sorted_ips(
        failures_per_ip.begin(), failures_per_ip.end());
    std::sort(sorted_ips.begin(), sorted_ips.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // --- Build JSON manually (no external lib dependency) ---
    std::ostringstream js;
    js << "{\n";
    js << "  \"epoch\": "              << epoch            << ",\n";
    js << "  \"total_failures\": "     << total_failures   << ",\n";
    js << "  \"total_successes\": "    << total_successes  << ",\n";
    js << "  \"failures_last_minute\": " << flm            << ",\n";

    // Full per-IP map
    js << "  \"failures_per_ip\": {";
    bool first = true;
    for (const auto& [ip, cnt] : failures_per_ip) {
        if (!first) js << ",";
        js << "\n    \"" << ip << "\": " << cnt;
        first = false;
    }
    js << "\n  },\n";

    // Top 10 IPs array
    js << "  \"top_ips\": [";
    int top_n = std::min(static_cast<int>(sorted_ips.size()), 10);
    for (int i = 0; i < top_n; ++i) {
        if (i > 0) js << ",";
        js << "\n    {\"ip\": \"" << sorted_ips[i].first
           << "\", \"count\": "  << sorted_ips[i].second << "}";
    }
    js << "\n  ]\n";

    js << "}\n";
    return js.str();
}

// ─── Main Loop ───────────────────────────────────────────────────────────────

void tail_and_parse(const std::string& log_path, const std::string& out_path) {
    // Use lower-level POSIX file operations for better tail-like behavior on macOS
    int fd = open(log_path.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[ssh_parser] WARNING: Cannot open " << log_path
                  << " – will retry...\n";
        fd = -1;
    }

    // Seek to end
    if (fd >= 0) {
        lseek(fd, 0, SEEK_END);
    }

    auto last_report = std::chrono::steady_clock::now();
    std::string accumulated;  // Buffer for partial lines
    char buffer[4096];

    std::cout << "[ssh_parser] Monitoring " << log_path << "\n";
    std::cout << "[ssh_parser] Writing JSON to " << out_path << "\n";

    while (g_running.load()) {
        // Try to read new data
        if (fd >= 0) {
            ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                accumulated.append(buffer, bytes_read);
                
                // Process complete lines
                size_t pos = 0;
                while ((pos = accumulated.find('\n')) != std::string::npos) {
                    std::string line = accumulated.substr(0, pos);
                    accumulated.erase(0, pos + 1);
                    
                    bool is_failure = false;
                    if (is_ssh_event(line, is_failure)) {
                        std::string ip   = extract_ip(line);
                        std::string user = extract_username(line);
                        record_event(is_failure, ip);

                        // Console log for visibility
                        std::cout << "[ssh_parser] "
                                  << (is_failure ? "FAIL" : " OK ")
                                  << " ip=" << (ip.empty() ? "?" : ip)
                                  << " user=" << user << "\n";
                    }
                }
            } else if (bytes_read < 0) {
                // Error reading; close and retry
                close(fd);
                fd = -1;
            }
        } else {
            // Retry opening the file
            fd = open(log_path.c_str(), O_RDONLY);
            if (fd >= 0) {
                lseek(fd, 0, SEEK_END);
                std::cout << "[ssh_parser] Opened " << log_path << "\n";
            }
        }

        // Write JSON summary at the configured interval
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_report).count();

        if (elapsed >= REPORT_INTERVAL) {
            std::string json = build_json();

            // Atomic write: write to .tmp then rename
            std::string tmp_path = out_path + ".tmp";
            {
                int out_fd = open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (out_fd >= 0) {
                    ssize_t written = write(out_fd, json.c_str(), json.length());
                    if (written > 0) {
                        fsync(out_fd);
                    }
                    close(out_fd);
                }
            }
            rename(tmp_path.c_str(), out_path.c_str());

            last_report = now;
        }

        // Small sleep to avoid busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (fd >= 0) {
        close(fd);
    }
    std::cout << "[ssh_parser] Shutting down.\n";
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::string log_path = DEFAULT_LOG_PATH;
    std::string out_path = DEFAULT_OUT_PATH;

    // Simple argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--log" || arg == "-l") && i + 1 < argc)
            log_path = argv[++i];
        else if ((arg == "--out" || arg == "-o") && i + 1 < argc)
            out_path = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: ssh_parser [--log PATH] [--out PATH]\n";
            std::cout << "\nOptions:\n";
            std::cout << "  --log, -l PATH    SSH auth log file path (auto-detected by OS)\n";
            std::cout << "  --out, -o PATH    JSON output file path (default: /shared/ssh_metrics.json)\n";
            std::cout << "\nPlatform defaults:\n";
            std::cout << "  Linux:   /var/log/auth.log\n";
            std::cout << "  macOS:   /var/log/system.log\n";
            return 0;
        }
    }

    std::cout << "╔══════════════════════════════════════════════╗\n"
              << "║   SSH Security Log Parser (C++ Service)      ║\n"
              << "╚══════════════════════════════════════════════╝\n";

    tail_and_parse(log_path, out_path);
    return 0;
}

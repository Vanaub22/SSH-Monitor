/**
 * parser.h - SSH Log Parser Header
 *
 * Defines the core data structures and the SshLogParser class
 * responsible for reading /var/log/auth.log, extracting SSH events,
 * and producing structured JSON summaries.
 *
 * Key data structures:
 *   - std::unordered_map<string, int>  for O(1) per-IP failure counting
 *   - Time-bucket map (minute granularity) for failures-per-minute
 */

#ifndef SSH_PARSER_H
#define SSH_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <ctime>
#include <mutex>

// ─── Structures ──────────────────────────────────────────────────────────────

/**
 * Represents a single parsed SSH event extracted from auth.log.
 */
struct SshEvent {
    std::string timestamp;      // Original log timestamp
    std::string source_ip;      // Attacker / client IP
    bool        is_failure;     // true = failed login, false = success
    std::string username;       // Target username (if available)
};

/**
 * JSON summary produced every reporting interval (default 1 s).
 * Written to the shared output file for the Python exporter to consume.
 */
struct JsonSummary {
    long        epoch;                                  // UNIX epoch seconds
    int         total_failures;                         // Cumulative failures
    int         total_successes;                        // Cumulative successes
    int         failures_last_minute;                   // Failures in the last 60 s
    std::unordered_map<std::string, int> failures_per_ip;  // IP → count
};

// ─── Parser Class ────────────────────────────────────────────────────────────

class SshLogParser {
public:
    explicit SshLogParser(const std::string& log_path);

    /**
     * Main loop: tail the log file, parse new lines, and write JSON
     * summaries to output_path every `interval_sec` seconds.
     */
    void run(const std::string& output_path, int interval_sec = 1);

private:
    // Parsing helpers
    bool        parse_line(const std::string& line, SshEvent& event);
    std::string extract_ip(const std::string& line);
    std::string extract_username(const std::string& line);

    // State update
    void record_event(const SshEvent& event);

    // JSON output
    std::string build_json() const;
    int         compute_failures_last_minute() const;

    // ── State ────────────────────────────────────────────────────────────
    std::string log_path_;

    int total_failures_  = 0;
    int total_successes_ = 0;

    // O(1) amortised lookup/insert – see README for complexity analysis
    std::unordered_map<std::string, int> failures_per_ip_;

    // minute-bucket → failure count   (key = epoch / 60)
    std::unordered_map<long, int>        failures_per_minute_;

    mutable std::mutex state_mutex_;
};

#endif // SSH_PARSER_H

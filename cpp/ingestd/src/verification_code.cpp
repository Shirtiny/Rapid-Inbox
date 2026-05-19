#include "verification_code.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace rapid_inbox::ingestd {
namespace {

constexpr double kScoreThreshold = 5.0;
constexpr double kTieMargin = 1.0;
constexpr std::size_t kContextRadius = 140;

struct Candidate {
    std::string code;
    std::string display;
    std::size_t start = 0;
    std::size_t end = 0;
    std::string shape;
    std::size_t length = 0;
};

bool ascii_space(unsigned char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

bool ascii_alnum(unsigned char ch) {
    return std::isalnum(ch) != 0;
}

bool ascii_digit(unsigned char ch) {
    return std::isdigit(ch) != 0;
}

bool parse_four_digit_year(std::string_view value, int& year) {
    if (value.size() != 4) {
        return false;
    }
    year = 0;
    for (unsigned char ch : value) {
        if (!ascii_digit(ch)) {
            return false;
        }
        year = year * 10 + (ch - '0');
    }
    return true;
}

int hex_value(unsigned char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

void append_utf8(std::string& output, int codepoint) {
    if (codepoint < 0 || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
        return;
    }
    if (codepoint <= 0x7f) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else if (codepoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    }
}

std::string lower_ascii(std::string_view value) {
    std::string lowered;
    lowered.reserve(value.size());
    for (unsigned char ch : value) {
        lowered.push_back(static_cast<char>(std::tolower(ch)));
    }
    return lowered;
}

std::string trim(std::string_view value) {
    std::size_t first = 0;
    while (first < value.size() && ascii_space(static_cast<unsigned char>(value[first]))) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first && ascii_space(static_cast<unsigned char>(value[last - 1]))) {
        --last;
    }
    return std::string(value.substr(first, last - first));
}

std::string normalize_whitespace(std::string_view source) {
    std::string normalized;
    normalized.reserve(source.size());
    bool pending_space = false;
    for (unsigned char ch : source) {
        if (ascii_space(ch)) {
            pending_space = !normalized.empty();
            continue;
        }
        if (pending_space) {
            normalized.push_back(' ');
            pending_space = false;
        }
        normalized.push_back(static_cast<char>(ch));
    }
    return normalized;
}

std::string normalize_body_text(std::string_view source) {
    std::string normalized;
    normalized.reserve(source.size());
    bool pending_space = false;
    bool pending_newline = false;
    for (std::size_t index = 0; index < source.size(); ++index) {
        const char ch = source[index];
        if (ch == '\r') {
            if (index + 1 < source.size() && source[index + 1] == '\n') {
                ++index;
            }
            pending_newline = !normalized.empty();
            pending_space = false;
            continue;
        }
        if (ch == '\n') {
            pending_newline = !normalized.empty();
            pending_space = false;
            continue;
        }
        if (ch == ' ' || ch == '\t' || ch == '\f' || ch == '\v') {
            pending_space = !normalized.empty();
            continue;
        }
        if (pending_newline) {
            if (!normalized.empty() && normalized.back() != '\n') {
                normalized.push_back('\n');
            }
            pending_newline = false;
        } else if (pending_space) {
            normalized.push_back(' ');
        }
        pending_space = false;
        normalized.push_back(ch);
    }
    return trim(normalized);
}

bool contains_any(std::string_view haystack, const std::vector<std::string_view>& needles) {
    for (std::string_view needle : needles) {
        if (haystack.find(needle) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

const std::vector<std::string_view>& hints() {
    static const std::vector<std::string_view> values = {
        "验证码",          "确认码",       "登录码",       "安全码",
        "动态密码",        "授权码",       "verification code",
        "verify code",     "security code", "login code",   "sign-in code",
        "sign in code",    "signin code",   "one-time code", "one time code",
        "otp",             "passcode",      "pass code",    "confirmation code",
        "temporary code",  "authentication code",           "authorization code",
        "verify your email",                "verify your account",
        "confirm your email",               "confirm your sign-in",
        "confirm your sign in",             "your code is",
        "code is",         "code:",         "enter this code",
        "enter the code",  "use this code", "please use the code",
        "code to verify",  "code to confirm", "code to continue",
        "enter the following",
        "code de v\xc3\xa9rification",
        "c\xc3\xb3digo de verificaci\xc3\xb3n",
        "codigo de verificacion",
        "best\xc3\xa4tigungscode",
        "codice di verifica",
        "\xe8\xaa\x8d\xe8\xa8\xbc\xe3\x82\xb3\xe3\x83\xbc\xe3\x83\x89",
        "\xe7\xa2\xba\xe8\xaa\x8d\xe3\x82\xb3\xe3\x83\xbc\xe3\x83\x89",
        "\xec\x9d\xb8\xec\xa6\x9d \xec\xbd\x94\xeb\x93\x9c",
        "\xec\x9d\xb8\xec\xa6\x9d\xec\xbd\x94\xeb\x93\x9c",
    };
    return values;
}

std::string replace_all(std::string value, std::string_view needle, std::string_view replacement) {
    std::size_t position = 0;
    while ((position = value.find(needle, position)) != std::string::npos) {
        value.replace(position, needle.size(), replacement);
        position += replacement.size();
    }
    return value;
}

std::string decode_basic_html_entities(std::string value) {
    value = replace_all(std::move(value), "&nbsp;", " ");
    value = replace_all(std::move(value), "&amp;", "&");
    value = replace_all(std::move(value), "&lt;", "<");
    value = replace_all(std::move(value), "&gt;", ">");
    value = replace_all(std::move(value), "&quot;", "\"");
    value = replace_all(std::move(value), "&#39;", "'");
    value = replace_all(std::move(value), "&apos;", "'");
    value = replace_all(std::move(value), "&mdash;", "-");

    std::string decoded;
    decoded.reserve(value.size());
    for (std::size_t index = 0; index < value.size();) {
        if (value[index] != '&' || index + 3 >= value.size() || value[index + 1] != '#') {
            decoded.push_back(value[index]);
            ++index;
            continue;
        }

        const bool hex = index + 4 < value.size() && (value[index + 2] == 'x' || value[index + 2] == 'X');
        std::size_t cursor = index + (hex ? 3 : 2);
        int codepoint = 0;
        bool valid_entity = true;
        bool has_digit = false;
        const int base = hex ? 16 : 10;
        while (cursor < value.size() && value[cursor] != ';') {
            const int digit = hex ? hex_value(static_cast<unsigned char>(value[cursor]))
                                  : (ascii_digit(static_cast<unsigned char>(value[cursor]))
                                         ? value[cursor] - '0'
                                         : -1);
            if (digit < 0) {
                valid_entity = false;
                break;
            }
            if (codepoint > (std::numeric_limits<int>::max() - digit) / base) {
                valid_entity = false;
                break;
            }
            has_digit = true;
            codepoint = codepoint * base + digit;
            ++cursor;
        }
        if (valid_entity && has_digit && cursor < value.size() && value[cursor] == ';') {
            append_utf8(decoded, codepoint);
            index = cursor + 1;
            continue;
        }

        decoded.push_back(value[index]);
        ++index;
    }
    return decoded;
}

bool tag_name_matches(std::string_view tag, std::string_view wanted) {
    std::size_t index = 0;
    if (index < tag.size() && tag[index] == '/') {
        ++index;
    }
    while (index < tag.size() && ascii_space(static_cast<unsigned char>(tag[index]))) {
        ++index;
    }
    if (index + wanted.size() > tag.size()) {
        return false;
    }
    if (lower_ascii(tag.substr(index, wanted.size())) != wanted) {
        return false;
    }
    const std::size_t next = index + wanted.size();
    return next == tag.size() || ascii_space(static_cast<unsigned char>(tag[next])) ||
           tag[next] == '>' || tag[next] == '/';
}

bool is_block_tag(std::string_view tag) {
    static const std::vector<std::string_view> block_tags = {
        "p",  "div", "h1", "h2", "h3", "h4", "h5",    "h6",   "li",
        "ul", "ol",  "tr", "td", "th", "table", "br", "hr",   "blockquote",
        "article", "section",
    };
    for (std::string_view name : block_tags) {
        if (tag_name_matches(tag, name)) {
            return true;
        }
    }
    return false;
}

std::string html_to_text(const std::string& source) {
    std::string output;
    output.reserve(source.size());
    const std::string lowered = lower_ascii(source);
    std::size_t index = 0;
    while (index < source.size()) {
        if (source[index] != '<') {
            output.push_back(source[index]);
            ++index;
            continue;
        }

        const std::size_t tag_end = source.find('>', index + 1);
        if (tag_end == std::string::npos) {
            output.push_back(' ');
            break;
        }

        const std::string_view tag(source.data() + index + 1, tag_end - index - 1);
        if (tag_name_matches(tag, "script") || tag_name_matches(tag, "style")) {
            const std::string close_tag = tag_name_matches(tag, "script") ? "</script>" : "</style>";
            const std::size_t close = lowered.find(close_tag, tag_end + 1);
            if (close == std::string::npos) {
                break;
            }
            index = close + close_tag.size();
            output.push_back(' ');
            continue;
        }
        if (is_block_tag(tag)) {
            output.push_back('\n');
        } else {
            output.push_back(' ');
        }
        index = tag_end + 1;
    }
    return decode_basic_html_entities(std::move(output));
}

void blank_range(std::string& value, std::size_t start, std::size_t end) {
    end = std::min(end, value.size());
    for (std::size_t index = start; index < end; ++index) {
        value[index] = ' ';
    }
}

std::size_t token_end(const std::string& value, std::size_t start) {
    std::size_t end = start;
    while (end < value.size() && !ascii_space(static_cast<unsigned char>(value[end]))) {
        ++end;
    }
    return end;
}

bool token_has_email_shape(std::string_view token) {
    const std::size_t at = token.find('@');
    return at != std::string_view::npos && token.find('.', at) != std::string_view::npos;
}

bool token_has_currency_marker(std::string_view token) {
    return token.find('$') != std::string_view::npos || token.find("¥") != std::string_view::npos ||
           token.find("￥") != std::string_view::npos || token.find("€") != std::string_view::npos ||
           token.find("£") != std::string_view::npos;
}

std::size_t skip_spaces(const std::string& value, std::size_t index) {
    while (index < value.size() && ascii_space(static_cast<unsigned char>(value[index]))) {
        ++index;
    }
    return index;
}

bool currency_marker_at(const std::string& value, std::size_t index, std::size_t& width) {
    const std::string_view tail(value.data() + index, value.size() - index);
    for (std::string_view marker : {"$", "¥", "￥", "€", "£"}) {
        if (tail.starts_with(marker)) {
            width = marker.size();
            return true;
        }
    }
    return false;
}

void blank_urls(std::string& value) {
    const std::string lowered = lower_ascii(value);
    std::size_t position = 0;
    while (position < lowered.size()) {
        const std::size_t http = lowered.find("http://", position);
        const std::size_t https = lowered.find("https://", position);
        std::size_t start = std::min(http == std::string::npos ? lowered.size() : http,
                                     https == std::string::npos ? lowered.size() : https);
        if (start >= lowered.size()) {
            break;
        }
        const std::size_t end = token_end(value, start);
        blank_range(value, start, end);
        position = end;
    }
}

void blank_currency_values(std::string& value) {
    for (std::size_t index = 0; index < value.size(); ++index) {
        std::size_t marker_width = 0;
        if (!currency_marker_at(value, index, marker_width)) {
            continue;
        }
        std::size_t end = index + marker_width;
        end = skip_spaces(value, end);
        bool saw_digit = false;
        while (end < value.size()) {
            const unsigned char ch = static_cast<unsigned char>(value[end]);
            if (ascii_digit(ch)) {
                saw_digit = true;
                ++end;
            } else if (ch == ',' || ch == '.') {
                ++end;
            } else {
                break;
            }
        }
        if (saw_digit) {
            blank_range(value, index, end);
            index = end;
        }
    }
}

bool date_separator(char ch) {
    return ch == '-' || ch == '/';
}

std::size_t consume_date_component(const std::string& value,
                                   std::size_t index,
                                   std::size_t min_digits,
                                   std::size_t max_digits) {
    const std::size_t start = index;
    while (index < value.size() && ascii_digit(static_cast<unsigned char>(value[index])) &&
           index - start < max_digits) {
        ++index;
    }
    const std::size_t count = index - start;
    return count >= min_digits ? index : start;
}

void blank_date_values(std::string& value) {
    for (std::size_t index = 0; index + 7 < value.size(); ++index) {
        if (index > 0 && ascii_alnum(static_cast<unsigned char>(value[index - 1]))) {
            continue;
        }
        int year = 0;
        if (!parse_four_digit_year(std::string_view(value).substr(index, 4), year) ||
            year < 1900 || year > 2099) {
            continue;
        }
        std::size_t cursor = index + 4;
        if (cursor >= value.size() || !date_separator(value[cursor])) {
            continue;
        }
        ++cursor;
        const std::size_t month_end = consume_date_component(value, cursor, 1, 2);
        if (month_end == cursor || month_end >= value.size() || !date_separator(value[month_end])) {
            continue;
        }
        cursor = month_end + 1;
        const std::size_t day_end = consume_date_component(value, cursor, 1, 2);
        if (day_end == cursor ||
            (day_end < value.size() && ascii_alnum(static_cast<unsigned char>(value[day_end])))) {
            continue;
        }
        blank_range(value, index, day_end);
        index = day_end;
    }
}

std::string strip_irrelevant_tokens(std::string text) {
    blank_urls(text);
    blank_currency_values(text);
    blank_date_values(text);

    for (std::size_t index = 0; index < text.size();) {
        if (ascii_space(static_cast<unsigned char>(text[index]))) {
            ++index;
            continue;
        }
        const std::size_t end = token_end(text, index);
        const std::string_view token(text.data() + index, end - index);
        if (token_has_email_shape(token) || token_has_currency_marker(token)) {
            blank_range(text, index, end);
        }
        index = end;
    }

    for (std::size_t index = 0; index < text.size();) {
        if (!ascii_digit(static_cast<unsigned char>(text[index]))) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < text.size() && ascii_digit(static_cast<unsigned char>(text[index]))) {
            ++index;
        }
        const std::size_t length = index - start;
        if (length >= 9) {
            blank_range(text, start, index);
            continue;
        }
    }

    return normalize_body_text(text);
}

bool looks_like_verification_message(const std::string& sender,
                                     const std::string& subject,
                                     const std::string& text) {
    const std::string lowered_text = lower_ascii(text);
    const std::string lowered_subject = lower_ascii(subject);
    if (contains_any(lowered_text, hints()) || contains_any(lowered_subject, hints())) {
        return true;
    }
    const std::string lowered_sender = lower_ascii(sender);
    static const std::vector<std::string_view> sender_hints = {
        "verify", "verification", "otp", "noreply", "no-reply", "account", "security", "accounts",
    };
    static const std::vector<std::string_view> subject_hints = {
        "code", "otp", "verify", "verification", "confirm", "sign in", "sign-in",
        "signin", "登录", "验证", "确认",
    };
    return contains_any(lowered_subject, subject_hints) && contains_any(lowered_sender, sender_hints);
}

std::string canonical_digits(std::string_view value) {
    std::string digits;
    digits.reserve(value.size());
    for (unsigned char ch : value) {
        if (ascii_digit(ch)) {
            digits.push_back(static_cast<char>(ch));
        }
    }
    return digits;
}

std::string canonical_alnum(std::string_view value) {
    std::string canonical;
    canonical.reserve(value.size());
    for (unsigned char ch : value) {
        if (ascii_alnum(ch)) {
            canonical.push_back(static_cast<char>(std::toupper(ch)));
        }
    }
    return canonical;
}

bool is_stop_word(const std::string& value) {
    static const std::unordered_set<std::string> stop_words = {
        "http",    "https",  "mail",    "email",  "gmail",    "yahoo",   "inbox",
        "code",    "codes",  "login",   "signup", "subject",  "header",  "sender",
        "client",  "please", "thanks",  "support", "notice",  "noreply", "account",
        "action",  "update", "confirm", "verify", "welcome",  "expire",  "expires",
        "token",   "secret", "minutes", "minute", "style",    "width",   "height",
        "table",   "title",  "class",   "message", "content", "report",  "server",
        "tracking", "order", "orders",  "shipment", "invoice", "receipt",
    };
    return stop_words.contains(lower_ascii(value));
}

void record_candidate(std::vector<Candidate>& results,
                      std::unordered_set<std::string>& seen,
                      std::string_view display,
                      std::size_t start,
                      std::size_t end,
                      const std::string& shape) {
    std::string code = shape == "alnum" ? canonical_alnum(display) : canonical_digits(display);
    if (shape == "digits" && !(code.size() >= 4 && code.size() <= 8)) {
        return;
    }
    if (shape == "grouped-digits" && !(code.size() >= 4 && code.size() <= 10)) {
        return;
    }
    if (shape == "alnum") {
        if (!(code.size() >= 4 && code.size() <= 10)) {
            return;
        }
        if (std::none_of(code.begin(), code.end(), [](unsigned char ch) { return ascii_digit(ch); })) {
            return;
        }
        if (std::all_of(code.begin(), code.end(), [](unsigned char ch) { return ascii_digit(ch); })) {
            return;
        }
        if (is_stop_word(code)) {
            return;
        }
    }
    if (code.empty() || seen.contains(code)) {
        return;
    }
    seen.insert(code);
    results.push_back(Candidate{
        .code = std::move(code),
        .display = std::string(display),
        .start = start,
        .end = end,
        .shape = shape,
        .length = 0,
    });
    results.back().length = results.back().code.size();
}

std::vector<Candidate> enumerate_candidates(const std::string& text) {
    std::vector<Candidate> results;
    std::unordered_set<std::string> seen;

    for (std::size_t index = 0; index < text.size();) {
        if (!ascii_digit(static_cast<unsigned char>(text[index])) ||
            (index > 0 && ascii_alnum(static_cast<unsigned char>(text[index - 1])))) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        bool has_separator = false;
        while (index < text.size()) {
            const unsigned char ch = static_cast<unsigned char>(text[index]);
            if (ascii_digit(ch)) {
                ++index;
            } else if (ch == '-' || ch == ' ') {
                has_separator = true;
                ++index;
            } else {
                break;
            }
        }
        std::size_t end = index;
        while (end > start && (text[end - 1] == '-' || text[end - 1] == ' ')) {
            --end;
        }
        if (end > start && (end >= text.size() ||
                            !ascii_alnum(static_cast<unsigned char>(text[end])))) {
            const std::string_view display(text.data() + start, end - start);
            record_candidate(results, seen, display, start, end,
                             has_separator ? "grouped-digits" : "digits");
        }
    }

    for (std::size_t index = 0; index < text.size();) {
        if (!ascii_alnum(static_cast<unsigned char>(text[index])) ||
            (index > 0 && ascii_alnum(static_cast<unsigned char>(text[index - 1])))) {
            ++index;
            continue;
        }
        const std::size_t start = index;
        while (index < text.size() && ascii_alnum(static_cast<unsigned char>(text[index]))) {
            ++index;
        }
        const std::size_t end = index;
        const std::string_view display(text.data() + start, end - start);
        record_candidate(results, seen, display, start, end, "alnum");
    }

    return results;
}

std::pair<bool, std::size_t> context_hit_nearby(const std::string& lowered,
                                                std::size_t start,
                                                std::size_t end) {
    const std::size_t window_start = start > kContextRadius ? start - kContextRadius : 0;
    const std::size_t window_end = std::min(lowered.size(), end + kContextRadius);
    const std::string_view window(lowered.data() + window_start, window_end - window_start);
    std::optional<std::size_t> best_distance;
    for (std::string_view hint : hints()) {
        const std::size_t found = window.find(hint);
        if (found == std::string_view::npos) {
            continue;
        }
        const std::size_t absolute = window_start + found;
        const std::size_t distance =
            absolute <= end ? (start > absolute + hint.size() ? start - (absolute + hint.size()) : 0)
                            : absolute - end;
        if (!best_distance.has_value() || distance < *best_distance) {
            best_distance = distance;
        }
    }
    return {best_distance.has_value(), best_distance.value_or(0)};
}

double score_candidate(const Candidate& candidate,
                       const std::string& subject,
                       const std::string& full_text,
                       const std::string& html_plain) {
    const std::string lowered = lower_ascii(full_text);
    const auto [has_hint, distance] = context_hit_nearby(lowered, candidate.start, candidate.end);

    double score = 0.0;
    if (has_hint) {
        score += 4.0;
        if (distance <= 6) {
            score += 4.0;
        } else if (distance <= 20) {
            score += 2.0;
        } else if (distance <= kContextRadius) {
            score += 1.0;
        }
    }

    const std::string subject_lower = lower_ascii(subject);
    if (!subject.empty() &&
        (subject.find(candidate.display) != std::string::npos ||
         subject.find(candidate.code) != std::string::npos)) {
        score += 2.5;
    }
    if (contains_any(subject_lower, hints())) {
        score += 1.5;
    }

    if (candidate.shape == "digits") {
        if (candidate.length == 6) {
            score += 2.0;
        } else if (candidate.length == 4 || candidate.length == 5 || candidate.length == 7) {
            score += 1.0;
        } else if (candidate.length == 8) {
            score += 0.8;
        }
    } else if (candidate.shape == "grouped-digits") {
        score += 1.8;
    } else if (candidate.shape == "alnum") {
        score += 0.6;
    }

    const std::size_t line_start = full_text.rfind('\n', candidate.start);
    const std::size_t line_begin = line_start == std::string::npos ? 0 : line_start + 1;
    const std::size_t line_end_found = full_text.find('\n', candidate.end);
    const std::size_t line_end =
        line_end_found == std::string::npos ? full_text.size() : line_end_found;
    const std::string line = trim(std::string_view(full_text).substr(line_begin, line_end - line_begin));
    if (line == candidate.display) {
        score += 2.5;
    } else if (line.size() <= 24 && line.find(candidate.display) != std::string::npos) {
        score += 1.0;
    }

    if (!html_plain.empty() && html_plain.find(candidate.display) != std::string::npos) {
        score += 0.2;
    }

    if (candidate.shape == "digits") {
        if (candidate.length == 4) {
            const int value = std::stoi(candidate.code);
            if (value >= 1900 && value <= 2100) {
                score -= 1.0;
            }
        }
        if (candidate.code == "0000" || candidate.code == "00000" ||
            candidate.code == "000000" || candidate.code == "1111" ||
            candidate.code == "111111" || candidate.code == "123456" ||
            candidate.code == "12345678") {
            score -= 2.0;
        }
        if (std::unordered_set<char>(candidate.code.begin(), candidate.code.end()).size() == 1) {
            score -= 2.0;
        }
    }

    return score;
}

bool is_in_disjunction(const std::string& text,
                       const Candidate& chosen,
                       const std::vector<Candidate>& candidates) {
    const std::size_t start = chosen.start > 80 ? chosen.start - 80 : 0;
    const std::size_t end = std::min(text.size(), chosen.end + 80);
    const std::string window = lower_ascii(std::string_view(text).substr(start, end - start));
    if (window.find(" or ") == std::string::npos && window.find("/") == std::string::npos &&
        window.find("\\") == std::string::npos && window.find("或") == std::string::npos &&
        window.find("或者") == std::string::npos) {
        return false;
    }
    for (const Candidate& peer : candidates) {
        if (peer.code != chosen.code && window.find(lower_ascii(peer.display)) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}  // namespace

std::optional<std::string> extract_verification_code(const std::string& subject,
                                                     const std::string& sender,
                                                     const std::string& text_body,
                                                     const std::string& html_body,
                                                     const std::string& preview) {
    const std::string subject_text = normalize_whitespace(subject);
    const std::string preview_text = normalize_body_text(preview);
    const std::string plain_text = normalize_body_text(text_body);
    const std::string html_plain = normalize_body_text(html_to_text(html_body));

    std::string context_text;
    for (const std::string* part : {&subject_text, &preview_text, &plain_text, &html_plain}) {
        if (!part->empty()) {
            if (!context_text.empty()) {
                context_text.push_back('\n');
            }
            context_text += *part;
        }
    }

    if (context_text.empty() ||
        !looks_like_verification_message(sender, subject_text, context_text)) {
        return std::nullopt;
    }

    const std::string cleaned_text = strip_irrelevant_tokens(context_text);
    if (cleaned_text.empty()) {
        return std::nullopt;
    }

    const std::vector<Candidate> candidates = enumerate_candidates(cleaned_text);
    if (candidates.empty()) {
        return std::nullopt;
    }

    std::optional<std::pair<double, std::size_t>> best;
    std::optional<std::pair<double, std::size_t>> runner_up;
    for (std::size_t index = 0; index < candidates.size(); ++index) {
        const double score = score_candidate(candidates[index], subject_text, cleaned_text, html_plain);
        if (score <= 0) {
            continue;
        }
        if (!best.has_value() || score > best->first) {
            runner_up = best;
            best = std::make_pair(score, index);
        } else if (!runner_up.has_value() || score > runner_up->first) {
            runner_up = std::make_pair(score, index);
        }
    }

    if (!best.has_value() || best->first < kScoreThreshold) {
        return std::nullopt;
    }
    const Candidate& chosen = candidates[best->second];
    if (runner_up.has_value() && runner_up->first >= kScoreThreshold &&
        std::abs(best->first - runner_up->first) < kTieMargin &&
        candidates[runner_up->second].code != chosen.code) {
        return std::nullopt;
    }
    if (is_in_disjunction(cleaned_text, chosen, candidates)) {
        return std::nullopt;
    }
    return chosen.code;
}

}  // namespace rapid_inbox::ingestd

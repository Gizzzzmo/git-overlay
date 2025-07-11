use regex::{escape, Regex};
use std::str::{Chars, FromStr};

fn glob_escape_next(it: &mut Chars, re_pattern: &mut String) -> bool {
    let view = it.as_str();
    let Some(_) = it.next() else {
        return false;
    };
    re_pattern.push_str(&escape(&view[..1]));
    return true;
}

/// Parses the given iterator, and pushes the corresponding regex to re_pattern, consuming all remaining
/// characters in the iterator that correspond to the glob range.
/// The character starting the range (and possibly an escaping backslash) must have been consumed by
/// the iterator at this point.
/// If the iterator is empty, or contains only exactly one more backslash '\', does nothing and returns false.
/// Otherwise returns true.
fn glob_parse_range(
    mut range_start: char,
    escape_start: bool,
    it: &mut Chars,
    re_pattern: &mut String,
) -> bool {
    let Some(mut range_end) = it.as_str().chars().next() else {
        return false;
    };
    if range_end == ']' {
        if escape_start {
            re_pattern.push('\\');
        }
        re_pattern.push(range_start);
        re_pattern.push('-');
        return true;
    }
    let escape_end = '\\' == range_end;
    if escape_end {
        range_end = match it.next() {
            None => return false,
            Some(c) => c,
        }
    }
    it.next();

    if range_start > range_end {
        return false;
    }
    if range_start == '/' && range_end == '/' {
        return true;
    }

    if range_start == '/' {
        range_start = '0';
    }
    if range_end == '/' {
        range_end = '.';
    }

    if escape_start {
        re_pattern.push('\\');
    }
    re_pattern.push(range_start);
    re_pattern.push('-');

    if range_start < '/' && range_end > '/' {
        re_pattern.push_str(".0-");
    }

    if escape_end {
        re_pattern.push('\\');
    }
    re_pattern.push(range_end);

    return true;
}

/// Parses a glob-bracket-expression, and creates the corresponding regex, pushing it to re_pattern.
/// The starting opening bracket must have already been consumed by the iterator.
/// Returns true if the iterator starts with a valid glob-bracket-expression.
/// Otherwise returns false, in which case re_pattern may or may not have been written to.
/// A valid glob-bracket-expression must be terminated by an unescaped closing bracket ']'
/// and contain at least one character.
fn glob_parse_brackets(it: &mut Chars, re_pattern: &mut String) -> bool {
    let peek_first = it.as_str().chars().next();
    if peek_first == Some(']') {
        // a range must contain at least one character
        return false;
    }
    re_pattern.push('[');

    if matches!(peek_first, Some('^') | Some('!')) {
        it.next();
        re_pattern.push_str("^/");
    }

    while let Some(c) = it.next() {
        match c {
            ']' => {
                re_pattern.push(']');
                return true;
            }
            '\\' => {
                let Some(next) = it.next() else {
                    // a backslash must escape something
                    return false;
                };
                if it.as_str().chars().next() == Some('-') {
                    it.next();
                    if !glob_parse_range(next, true, it, re_pattern) {
                        return false;
                    }
                } else {
                    re_pattern.push('\\');
                    re_pattern.push(next);
                }
            }
            c => {
                if it.as_str().chars().next() == Some('-') {
                    it.next();
                    if !glob_parse_range(c, false, it, re_pattern) {
                        return false;
                    }
                } else {
                    re_pattern.push(c);
                }
            }
        }
    }
    return false;
}

/// Turns a prefix string and a valid glob pattern into the corresponding regular expression
/// that matches what the glob pattern would match relative to the prefix string.
/// Also returns a bool that is true when the pattern ended in two asterisks
/// (in which case it should only matched against files, not directories).
/// Invalid glob patterns will return None.
pub fn glob_to_regex(pattern: &str, prefix: &str) -> Option<(Regex, bool)> {
    let mut re_pattern = String::new();
    re_pattern.reserve(pattern.len());
    let mut it = pattern.chars();

    let mut had_separator = false;
    let mut beginning = &pattern[..pattern.len().min(3)];

    if pattern.chars().next() == Some('/') {
        had_separator = true;
        it.next();
        beginning = &pattern[1..pattern.len().min(4)];
    }

    if beginning == "**/" {
        it.nth(2);
        re_pattern.push_str("(.*/|)");
        had_separator = true;
    }

    let mut last_pos: &str = it.as_str();
    let mut count = 0;
    let mut only_files = false;
    while let Some(c) = it.next() {
        if count > 0 && matches!(c, '*' | '?' | '[' | '\\') {
            re_pattern.push_str(&escape(&last_pos[..count]));
            count = 0;
        }
        match c {
            '/' => {
                had_separator = true;
                let peek_str = it.as_str().chars().as_str();
                let next_three = &peek_str[..peek_str.len().min(3)];

                if next_three != "**" && next_three != "**/" {
                    count += c.len_utf8();
                    continue;
                }

                if count > 0 {
                    re_pattern.push_str(&escape(&last_pos[..count]));
                    count = 0;
                }

                re_pattern.push_str("/.*");
                if next_three == "**" {
                    only_files = true;
                    break;
                }
                re_pattern.push('/');
                it.nth(2);
            }
            '*' => re_pattern.push_str("[^/]*"),
            '?' => re_pattern.push_str("[^/]"),
            '[' => {
                if !glob_parse_brackets(&mut it, &mut re_pattern) {
                    return None;
                }
            }
            '\\' => {
                if !glob_escape_next(&mut it, &mut re_pattern) {
                    return None;
                }
            }
            _ => {
                count += c.len_utf8();
                continue;
            }
        };
        last_pos = it.as_str();
    }

    if count > 0 {
        re_pattern.push_str(&escape(&last_pos[..count]));
    }

    let escaped_prefix = escape(&prefix);
    let last_char = prefix.chars().last();
    let need_extra_separator = last_char != Some('/') && last_char != None;

    let to_reserve = escaped_prefix.len()
        + if need_extra_separator { 1 } else { 0 }
        + if had_separator { 0 } else { "(.*/|)".len() }
        + re_pattern.len()
        + 1;

    let mut full_pattern = String::from_str("^").unwrap();
    full_pattern.reserve(to_reserve);

    full_pattern.push_str(&escaped_prefix);
    if need_extra_separator {
        full_pattern.push('/');
    }
    if !had_separator {
        full_pattern.push_str("(.*/|)");
    }
    full_pattern.push_str(&re_pattern);
    full_pattern.push('$');

    return Some((Regex::new(&full_pattern).unwrap(), only_files));
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn glob_to_regex_brackets() {
        let mut out = String::new();
        glob_parse_brackets(&mut "a-]".chars(), &mut out);
        assert_eq!(out.as_str(), "[a-]");
    }
    fn assert_glob_is_regex(glob: &str, expected_re: Option<&str>) {
        let regex = glob_to_regex(glob, "");
        let re_pattern = regex.as_ref().map(|(re, _)| re.as_str());

        assert_eq!(re_pattern, expected_re);
    }

    #[test]
    fn glob_to_regex_test() {
        assert_glob_is_regex("blub", Some("^(.*/|)blub$"));
        assert_glob_is_regex("/blub", Some("^blub$"));
        assert_glob_is_regex("**/blub", Some("^(.*/|)blub$"));
        assert_glob_is_regex("blab/blub", Some("^blab/blub$"));
        assert_glob_is_regex("**/blab/blub", Some("^(.*/|)blab/blub$"));
        assert_glob_is_regex("/**/blab/blub", Some("^(.*/|)blab/blub$"));
        assert_glob_is_regex("blab/blub/**", Some("^blab/blub/.*$"));
        assert_glob_is_regex("blab/**/blub", Some("^blab/.*/blub$"));

        assert_glob_is_regex("blab/*/blub", Some("^blab/[^/]*/blub$"));
        assert_glob_is_regex("blab/*blub", Some("^blab/[^/]*blub$"));
        assert_glob_is_regex("blab/?blub", Some("^blab/[^/]blub$"));

        // double star in path component
        assert_glob_is_regex("**blub", Some("^(.*/|)[^/]*[^/]*blub$"));
        assert_glob_is_regex("/**blub", Some("^[^/]*[^/]*blub$"));
        assert_glob_is_regex("blab/**blub", Some("^blab/[^/]*[^/]*blub$"));
        assert_glob_is_regex("**blub/blab", Some("^[^/]*[^/]*blub/blab$"));

        // remove separator from ranges
        assert_glob_is_regex("/[/-a]", Some("^[0-a]$"));
        assert_glob_is_regex("/[+-/]", Some("^[+-.]$"));
        assert_glob_is_regex("/[+-a]", Some("^[+-.0-a]$"));
        assert_glob_is_regex("/[^a]", Some("^[^/a]$"));
        assert_glob_is_regex("/[!a]", Some("^[^/a]$"));

        // invalid ranges
        assert_glob_is_regex("[a-+]", None);
        assert_glob_is_regex("[z-a]", None);
        assert_glob_is_regex("[.-+]", None);
        assert_glob_is_regex("[]", None);
        assert_glob_is_regex("[", None);
        assert_glob_is_regex("[\\]", None);

        // other range stuff
        assert_glob_is_regex("/[-a]", Some("^[-a]$"));
        assert_glob_is_regex("/[a-]", Some("^[a-]$"));
        assert_glob_is_regex("/[\\]]", Some("^[\\]]$"));

        // regex escaping
        assert_glob_is_regex(".", Some("^(.*/|)\\.$"));
        assert_glob_is_regex("/.", Some("^\\.$"));
        assert_glob_is_regex("/+", Some("^\\+$"));
        assert_glob_is_regex("/(", Some("^\\($"));
        assert_glob_is_regex("/$", Some("^\\$$"));
        assert_glob_is_regex("/^", Some("^\\^$"));

        // glob and regex escaping
        assert_glob_is_regex("/\\*", Some("^\\*$"));
        assert_glob_is_regex("/\\?", Some("^\\?$"));
        assert_glob_is_regex("/\\[", Some("^\\[$"));
        assert_glob_is_regex("/\\\\", Some("^\\\\$"));

        // glob escaping
        assert_glob_is_regex("/\\blub", Some("^blub$"));
    }
}

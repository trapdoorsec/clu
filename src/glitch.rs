use rand::Rng;
use std::collections::HashMap;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use owo_colors::OwoColorize;

/// Mapping of regular characters to l33t speak alternatives
fn leet_map() -> HashMap<char, Vec<char>> {
    let mut map = HashMap::new();
    map.insert('a', vec!['4', '@', 'Δ', 'α']);
    map.insert('A', vec!['4', '@', 'Δ', 'Λ']);
    map.insert('e', vec!['3', '€', 'ε', '£']);
    map.insert('E', vec!['3', '€', 'Ξ', 'Σ']);
    map.insert('i', vec!['1', '!', '|', 'í']);
    map.insert('I', vec!['1', '!', '|', 'Ì']);
    map.insert('o', vec!['0', 'ø', 'Ω', '°']);
    map.insert('O', vec!['0', 'Ø', 'Θ', '°']);
    map.insert('s', vec!['5', '$', 'ß', '§']);
    map.insert('S', vec!['5', '$', 'Š', '§']);
    map.insert('t', vec!['7', '+', '†', 'ţ']);
    map.insert('T', vec!['7', '+', '†', 'Ŧ']);
    map.insert('l', vec!['1', '|', 'ł', 'ļ']);
    map.insert('L', vec!['1', '|', 'Ł', '£']);
    map.insert('g', vec!['9', '6', 'ģ', 'ğ']);
    map.insert('G', vec!['9', '6', 'Ģ', 'Ğ']);
    map.insert('b', vec!['8', 'ß', 'þ', 'ḅ']);
    map.insert('B', vec!['8', 'ß', 'Þ', 'ß']);
    map.insert('c', vec!['¢', 'ç', '(', 'č']);
    map.insert('C', vec!['¢', 'Ç', '(', 'Ć']);
    map.insert('d', vec!['đ', 'ď', 'Ð', 'ð']);
    map.insert('D', vec!['Đ', 'Ď', 'Ð', 'Ð']);
    map.insert('n', vec!['ñ', 'ň', 'η', 'ņ']);
    map.insert('N', vec!['Ñ', 'Ň', 'Ń', 'Π']);
    map.insert('u', vec!['µ', 'ü', 'ù', 'û']);
    map.insert('U', vec!['Ü', 'Ù', 'Û', 'Ų']);
    map.insert('p', vec!['þ', 'ρ', 'þ', 'ṕ']);
    map.insert('P', vec!['Þ', 'Ṕ', 'Ṗ', 'ρ']);
    map.insert('h', vec!['#', 'ħ', 'ĥ', 'ḥ']);
    map.insert('H', vec!['#', 'Ħ', 'Ĥ', 'Η']);
    map.insert('m', vec!['М', 'ṁ', 'ɱ', 'ḿ']);
    map.insert('M', vec!['М', 'Ṁ', 'Ṃ', 'ʍ']);
    map.insert('f', vec!['ƒ', 'ḟ', 'ғ', 'ḟ']);
    map.insert('F', vec!['Ƒ', 'Ḟ', 'Ғ', 'Ḟ']);
    map.insert('y', vec!['¥', 'ý', 'ÿ', 'ŷ']);
    map.insert('Y', vec!['¥', 'Ý', 'Ÿ', 'Ŷ']);
    map
}

/// Apply random l33t speak glitch to a character with given intensity (0.0 = no glitch, 1.0 = max glitch)
fn glitch_char(c: char, intensity: f32, map: &HashMap<char, Vec<char>>) -> char {
    let mut rng = rand::thread_rng();

    // Random chance to glitch based on intensity
    if rng.r#gen::<f32>() > intensity {
        return c;
    }

    // Try to find a l33t replacement
    if let Some(replacements) = map.get(&c)
        && !replacements.is_empty() {
            let idx = rng.gen_range(0..replacements.len());
            return replacements[idx];
        }

    c
}

/// Apply glitch effect to entire text
#[allow(dead_code)]
fn glitch_text(text: &str, intensity: f32) -> String {
    let map = leet_map();
    text.chars()
        .map(|c| glitch_char(c, intensity, &map))
        .collect()
}

/// Clear terminal screen
fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
}

/// Print text at current cursor position with optional color
#[allow(dead_code)]
pub fn print_glitched(text: &str, use_color: bool) {
    let glitched = glitch_text(text, 0.8);
    if use_color {
        print!("{}", glitched.cyan());
    } else {
        print!("{}", glitched);
    }
    io::stdout().flush().unwrap();
}

/// Animate text with decreasing glitch intensity
#[allow(dead_code)]
pub fn glitch_animate(text: &str, frames: usize, frame_duration_ms: u64, use_color: bool) {
    let intensities = (0..frames)
        .map(|i| 1.0 - (i as f32 / frames as f32))
        .collect::<Vec<f32>>();

    for intensity in intensities {
        clear_screen();
        let glitched = glitch_text(text, intensity);

        if use_color {
            print!("{}", glitched.cyan());
        } else {
            print!("{}", glitched);
        }

        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_millis(frame_duration_ms));
    }

    // Final frame with no glitch
    clear_screen();
    if use_color {
        print!("{}", text.cyan());
    } else {
        print!("{}", text);
    }
    io::stdout().flush().unwrap();
}

// because why not
pub fn matrix_glitch(text: &str, iterations: usize, use_color: bool) {
    let mut rng = rand::thread_rng();
    let map = leet_map();

    for i in 0..iterations {
        clear_screen();

        // Decrease glitch probability as we progress
        let base_intensity = 1.0 - (i as f32 / iterations as f32);

        let glitched: String = text.chars()
            .map(|c| {
                // Each character has independent glitch chance
                let char_intensity = base_intensity * rng.r#gen::<f32>();
                glitch_char(c, char_intensity, &map)
            })
            .collect();

        if use_color {
            print!("{}", glitched.cyan());
        } else {
            print!("{}", glitched);
        }

        io::stdout().flush().unwrap();

        // Speed up as we approach the end
        let delay = ((100.0 * (1.0 - i as f32 / iterations as f32)) as u64).max(10);
        thread::sleep(Duration::from_millis(delay));
    }

    // Final clean frame
    clear_screen();
    if use_color {
        print!("{}", text.cyan());
    } else {
        print!("{}", text);
    }
    io::stdout().flush().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glitch_text_no_intensity() {
        let text = "hello";
        let result = glitch_text(text, 0.0);
        // With 0 intensity, should mostly be original (though random, so we just check length)
        assert_eq!(result.len(), text.len());
    }

    #[test]
    fn test_leet_map_contains_vowels() {
        let map = leet_map();
        assert!(map.contains_key(&'a'));
        assert!(map.contains_key(&'e'));
        assert!(map.contains_key(&'i'));
        assert!(map.contains_key(&'o'));
    }
}

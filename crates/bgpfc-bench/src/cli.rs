//! Command-line flags for the tools, from `std::env::args`: `--name value`
//! (or `--name=value`) pairs and bare `--name` switches.

use std::str::FromStr;

/// The arguments, with a note of which have been consumed.
#[derive(Debug)]
pub struct Flags {
    args: Vec<String>,
    used: Vec<bool>,
}

impl Flags {
    /// Flags from a list of arguments (without the program name).
    #[must_use]
    pub fn new(args: Vec<String>) -> Flags {
        let used = vec![false; args.len()];
        Flags { args, used }
    }

    /// Flags from the process arguments.
    #[must_use]
    pub fn from_env() -> Flags {
        Flags::new(std::env::args().skip(1).collect())
    }

    /// Whether the switch `name` is present.
    pub fn switch(&mut self, name: &str) -> bool {
        let mut found = false;
        for (a, u) in self.args.iter().zip(&mut self.used) {
            if a == name {
                *u = true;
                found = true;
            }
        }
        found
    }

    /// The value of `name`, if given; the last one wins.
    ///
    /// # Errors
    /// When `name` is the last argument and has no value.
    pub fn value(&mut self, name: &str) -> Result<Option<String>, String> {
        let mut out = None;
        let mut i = 0;
        while i < self.args.len() {
            let a = &self.args[i];
            if a == name {
                let v = self
                    .args
                    .get(i + 1)
                    .ok_or_else(|| format!("{name} needs a value"))?;
                out = Some(v.clone());
                self.used[i] = true;
                self.used[i + 1] = true;
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                out = Some(v.to_owned());
                self.used[i] = true;
            }
            i += 1;
        }
        Ok(out)
    }

    /// The value of `name` parsed as `T`, if given.
    ///
    /// # Errors
    /// A missing or unparsable value.
    pub fn get<T: FromStr>(&mut self, name: &str) -> Result<Option<T>, String> {
        self.value(name)?
            .map(|v| v.parse().map_err(|_| format!("bad value for {name}: {v}")))
            .transpose()
    }

    /// The value of `name` parsed as `T`, or `default`.
    ///
    /// # Errors
    /// A missing or unparsable value.
    pub fn get_or<T: FromStr>(&mut self, name: &str, default: T) -> Result<T, String> {
        Ok(self.get(name)?.unwrap_or(default))
    }

    /// Fail on anything not consumed.
    ///
    /// # Errors
    /// The first unknown argument.
    pub fn finish(&self) -> Result<(), String> {
        match self.args.iter().zip(&self.used).find(|(_, u)| !**u) {
            Some((a, _)) => Err(format!("unknown argument {a}")),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(s: &str) -> Flags {
        Flags::new(s.split_whitespace().map(str::to_owned).collect())
    }

    #[test]
    fn values_switches_and_leftovers() {
        let mut f = flags("--runs 3 --extended --seed=9 --scenario flap --runs 5");
        assert_eq!(f.get_or("--runs", 1u32), Ok(5));
        assert!(f.switch("--extended"));
        assert!(!f.switch("--missing"));
        assert_eq!(f.get::<u64>("--seed"), Ok(Some(9)));
        assert_eq!(f.value("--scenario"), Ok(Some("flap".to_owned())));
        assert_eq!(f.finish(), Ok(()));

        let mut f = flags("--runs x --bogus");
        assert!(f.get::<u32>("--runs").is_err());
        assert_eq!(f.finish(), Err("unknown argument --bogus".to_owned()));
        assert!(flags("--runs").value("--runs").is_err());
    }
}

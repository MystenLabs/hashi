// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Questions to the operator before a step changes anything.

use std::io;
use std::io::BufRead;
use std::io::IsTerminal;
use std::io::Write;

use anyhow::Result;
use anyhow::bail;

pub trait Ask {
    /// Whether stdin and stdout are a terminal, as a step that must be watched requires.
    fn interactive(&self) -> bool;

    /// The line typed after `prompt`, or `None` when stdin has closed.
    fn line(&self, prompt: &str) -> io::Result<Option<String>>;
}

/// The operator at the terminal.
pub struct Terminal;

impl Ask for Terminal {
    fn interactive(&self) -> bool {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }

    fn line(&self, prompt: &str) -> io::Result<Option<String>> {
        // Discard what was typed before the question was shown, so it can't answer it.
        // SAFETY: tcflush takes no pointers; it only drops the terminal's unread input.
        if io::stdin().is_terminal()
            && unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        print!("{prompt}");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim_end_matches(['\n', '\r']).to_owned()))
    }
}

/// What a step says when the operator doesn't go ahead: on no input, and on any answer but the one asked for.
pub struct Unchanged {
    pub no_input: &'static str,
    pub declined: &'static str,
}

/// The usual wording, for steps that would have changed anything.
pub const NOTHING_CHANGED: Unchanged = Unchanged {
    no_input: "No input received; nothing was changed.",
    declined: "Not confirmed; nothing was changed.",
};

/// Asks for y/yes, and stops on anything else.
pub fn confirm(ask: &dyn Ask, question: &str, unchanged: &Unchanged) -> Result<()> {
    match ask.line(&format!("{question} Type y/yes to continue: "))? {
        None => bail!("{}", unchanged.no_input),
        Some(answer) if answer == "y" || answer == "yes" => Ok(()),
        Some(_) => bail!("{}", unchanged.declined),
    }
}

/// Asks the operator to type `expected`, such as the instance ID a step would destroy, and stops on anything else.
pub fn confirm_typed(
    ask: &dyn Ask,
    expected: &str,
    purpose: &str,
    unchanged: &Unchanged,
) -> Result<()> {
    match ask.line(&format!("Type {expected} {purpose}: "))? {
        None => bail!("{}", unchanged.no_input),
        Some(typed) if typed == expected => Ok(()),
        Some(_) => bail!("{}", unchanged.declined),
    }
}

#[cfg(test)]
pub mod scripted {
    //! Answers given in advance, recording each prompt.

    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;

    /// A terminal nobody answers at.
    pub struct NoAnswers;

    pub static NO_ANSWERS: NoAnswers = NoAnswers;

    impl Ask for NoAnswers {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, _prompt: &str) -> io::Result<Option<String>> {
            Ok(None)
        }
    }

    /// No terminal at all, as when a step runs from a script.
    pub struct NoTerminal;

    impl Ask for NoTerminal {
        fn interactive(&self) -> bool {
            false
        }

        fn line(&self, _prompt: &str) -> io::Result<Option<String>> {
            Ok(None)
        }
    }

    #[derive(Default)]
    pub struct Scripted {
        answers: RefCell<VecDeque<String>>,
        pub prompts: RefCell<Vec<String>>,
    }

    impl Scripted {
        pub fn new(answers: &[&str]) -> Self {
            Self {
                answers: RefCell::new(answers.iter().map(|answer| (*answer).to_owned()).collect()),
                prompts: RefCell::default(),
            }
        }
    }

    impl Ask for Scripted {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, prompt: &str) -> io::Result<Option<String>> {
            self.prompts.borrow_mut().push(prompt.to_owned());
            Ok(self.answers.borrow_mut().pop_front())
        }
    }

    #[test]
    fn confirms_only_y_or_yes() {
        assert!(confirm(&Scripted::new(&["yes"]), "Go?", &NOTHING_CHANGED).is_ok());
        assert!(confirm(&Scripted::new(&["y"]), "Go?", &NOTHING_CHANGED).is_ok());
        for answer in ["Y", "yes please", "", "no"] {
            assert_eq!(
                confirm(&Scripted::new(&[answer]), "Go?", &NOTHING_CHANGED)
                    .unwrap_err()
                    .to_string(),
                "Not confirmed; nothing was changed."
            );
        }
        let ask = Scripted::new(&[]);
        assert_eq!(
            confirm(&ask, "Go?", &NOTHING_CHANGED)
                .unwrap_err()
                .to_string(),
            "No input received; nothing was changed."
        );
        assert_eq!(ask.prompts.borrow()[0], "Go? Type y/yes to continue: ");
        assert!(
            confirm_typed(
                &Scripted::new(&["i-0aaa"]),
                "i-0aaa",
                "to stop it",
                &NOTHING_CHANGED
            )
            .is_ok()
        );
        assert!(
            confirm_typed(
                &Scripted::new(&["i-0aab"]),
                "i-0aaa",
                "to stop it",
                &NOTHING_CHANGED
            )
            .is_err()
        );
    }
}

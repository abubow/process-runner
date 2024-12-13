use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;

fn main() -> std::io::Result<()> {
    // Spawn the Python process
    let mut child = Command::new("python3")
        .arg("-i") // Interactive mode
        .stdin(Stdio::piped()) // Allow writing to stdin
        .stdout(Stdio::piped()) // Capture stdout
        .stderr(Stdio::piped()) // Capture stderr (optional)
        .spawn()
        .expect("Failed to spawn Python process");

    // Get handles to the child's stdin and stdout
    let mut child_stdin = child.stdin.take().expect("Failed to open stdin");
    let child_stdout = child.stdout.take().expect("Failed to open stdout");

    // Use a thread to continuously read the process's output
    let output_reader = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line in reader.lines() {
            match line {
                Ok(output) => println!("Python says: {}", output),
                Err(e) => eprintln!("Error reading output: {}", e),
            }
        }
    });

    // Write commands to the Python process
    let commands = vec![
        "print('Hello from Python')",
        "x = 42",
        "print(f'The answer is {x}')",
        "import time; time.sleep(1)", // Simulate a delay
        "print('Goodbye from Python')",
    ];

    for command in commands {
        writeln!(child_stdin, "{}", command).expect("Failed to write to stdin");
        child_stdin.flush().expect("Failed to flush stdin");
    }

    // Close stdin to signal the end of input
    drop(child_stdin);

    // Wait for the output reader to finish
    output_reader.join().expect("Failed to join output thread");

    // Wait for the Python process to exit
    let status = child.wait()?;
    println!("Python process exited with status: {}", status);

    Ok(())
}
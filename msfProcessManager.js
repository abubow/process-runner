const pty = require("node-pty");

/**
 * Manages multiple instances of the Metasploit console process, allowing for
 * process control (start, command, stop) via `MsfProcess` and `MsfProcessFactory`.
 * 
 * - `MsfProcess`: Handles a single Metasploit process, managing commands, output, 
 *   and automatic stop due to inactivity.
 * - `MsfProcessFactory`: Manages multiple `MsfProcess` instances, allowing for
 *   retrieval, creation, and stopping of processes based on a source (e.g., CLI, RadialMenu).
 *   Tracks active processes and maintains centralized process control.
 * - `For radialMenu modules data, perform sequential commands execution, read response and return the response to broadcastOutput
 *    and insert it into parse
 * 
 * Dependencies: Uses `node-pty` to spawn and interact with pseudo-terminal processes.
 */

class MsfProcess {
  constructor(source) {
    this.source = source;
    this.process = null;
    this.lastCommandTimestamp = null;
    this.inactivityTimeout = null;
    this.commandQueue = [];
    this.radialDataCommandQueue = [];
    this.isExecutingCommands = false;
    this.isExecutingRadialDataCommands = false;
  }

  start(broadcastOutput) {
    if (this.process) {
      throw new Error(`${this.source}: Metasploit is already running`);
    }

    this.process = pty.spawn("msfconsole", [], {
      name: "xterm-color",
      cols: 80,
      rows: 30,
    });

    this.resetInactivityTimer();
    this.process.on("data", (data) => {
      const chunkString = data.toString();
      console.log("This is the chunk string--", chunkString);
      broadcastOutput(this.source, chunkString);
    });

    this.process.on("error", (error) => {
      console.error(`${this.source}: Error starting Metasploit: ${error.message}`);
    });

    this.process.on("exit", (code, signal) => {
      this.process = null;
      this.clearInactivityTimer();
    });

    return `${this.source}: Metasploit process starting...`;
  }

  enqueueCommand(command) {
    this.commandQueue.push(command);
    this.executeQueuedCommands();
  }

  enqueueRadialDataCommand(command) {
    this.radialDataCommandQueue.push(command);
    this.executeRadialDataQueuedCommands();
  }

  async executeQueuedCommands() {
    if (this.isExecutingCommands || !this.process) return;
    this.isExecutingCommands = true;

    while (this.commandQueue.length > 0) {
      const command = this.commandQueue.shift();
      console.debug(`Executing command for ${this.source}: ${command}`);

      try {
        await this.runCommand(command);
        await new Promise(resolve => setTimeout(resolve, 10000));
      } catch (error) {
        console.error(`${this.source}: Failed to execute command '${command}': ${error.message}`);
      }
    }

    this.isExecutingCommands = false;
  }

  async executeRadialDataQueuedCommands() {
    if (this.isExecutingRadialDataCommands || !this.process) return;
    this.isExecutingRadialDataCommands = true;

    while (this.radialDataCommandQueue.length > 0) {
      const command = this.radialDataCommandQueue.shift();
      console.debug(`Executing command for ${this.source}: ${command}`);

      try {
        await this.runCommand(command);
        await new Promise(resolve => setTimeout(resolve, 20000));
      } catch (error) {
        console.error(`${this.source}: Failed to execute command '${command}': ${error.message}`);
      }
    }

    this.isExecutingCommands = false;
  }

  runCommand(command) {
    return new Promise((resolve, reject) => {
      console.debug("Coming into run command to execute the commands");
      if (!this.process) {
        return reject(new Error(`${this.source}: Metasploit is not running`));
      }

      this.resetInactivityTimer();
      this.process.write(`${command}\n`);
      resolve();
    });
  }

  stop() {
    if (!this.process) {
      throw new Error(`${this.source}: Metasploit is not running`);
    }

    try {
      this.process.kill("SIGTERM");
      this.process.on("exit", () => {
        console.log(`${this.source}: Metasploit process stopped cleanly.`);
      });

    } catch (err) {
      console.error(`${this.source}: Error while attempting to stop: ${err.message}`);
    }

    this.process = null;
    this.clearInactivityTimer();
    return `${this.source}: Metasploit stopped`;
  }

  resetInactivityTimer() {
    this.clearInactivityTimer();

    this.inactivityTimeout = setTimeout(() => {
      console.log(`${this.source}: Stopping Metasploit due to inactivity`);
      this.stop();
    }, 10 * 60 * 1000);
  }

  clearInactivityTimer() {
    if (this.inactivityTimeout) {
      clearTimeout(this.inactivityTimeout);
      this.inactivityTimeout = null;
    }
  }
}

// Factory to create instances of MsfProcess for CLI or RadialMenu or any other future implementation
class MsfProcessFactory {
  constructor() {
    this.processes = {};
  }

  getProcess(source) {
    return this.processes[source];
  }

  setProcess(source, process) {
    this.processes[source] = process;
  }

  createProcess(source) {
    if (!this.processes[source]) {
      this.processes[source] = new MsfProcess(source);
    }
    return this.processes[source];
  }

  getRunningProcessesCount() {
    const runningProcesses = [];
    let runningCount = 0;

    for (const source in this.processes) {
      if (this.processes[source].process) {
        runningProcesses.push(source);
        runningCount++;
      }
    }

    const response = {
      "Number of processes running": runningCount,
      "Active Running Processes": runningProcesses
    };

    return response;
  }

  startProcess(source,broadcastOutput) {
    const process = this.createProcess(source);
    return process.start(broadcastOutput);
  }

  async runCommandForProcess(source, command, broadcastOutput) {
    const process = this.getProcess(source);
    if (!process) {
      throw new Error(`${source}: Metasploit is not running`);
    }

    if (source === "RadialMenu") {

      if(Array.isArray(command)){
        command.forEach(commands => process.enqueueCommand(commands));
      }
      else {
        return await process.runCommand(command);
      }
      
    } else if (source === "RadialModulesData") {
      console.debug("Coming into run command for process for modules data to execute the commands");
      command.forEach(commands => process.enqueueRadialDataCommand(commands));
    } else {
      if (Array.isArray(command)) {
        for (const commands of command) {
          return await process.runCommand(commands);
        }
      } else {
        return await process.runCommand(command);
      }
    }
  }

  stopProcess(source) {
    const process = this.getProcess(source);
    if (!process) {
      throw new Error(`${source}: Metasploit is not running`);
    }
    const message =  process.stop();
    setTimeout(() => {
      delete this.processes[source];
    }, 1000);

    return message;
  }
}

const msfProcessFactory = new MsfProcessFactory();
module.exports = { msfProcessFactory };

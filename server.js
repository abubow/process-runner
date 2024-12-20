// External imports
const Parse = require("parse/node");
const express = require("express");
const { WebSocketServer } = require("ws");
const fs = require("fs");
const path = require("path");

// Internal imports
const { msfProcessFactory } = require("./msfProcessManager.js");

const app = express();
app.use(express.json());

let currentCommandIndex = 0;
let commandIdentifier = false;
let radialOptionsDataIdentifier = false;
const modulesCommandsArray = ["show exploits", "show payloads", "show auxiliary"];

const parseConfig = {
  0: { className: "Exploits", idField: "exploitId" },
  1: { className: "Payloads", idField: "payloadId" },
  2: { className: "Auxiliary", idField: "auxiliaryId" }
};

Parse.initialize(
  process.env.APP_ID || "APP_ID",
  process.env.JAVASCRIPT_KEY || "JAVASCRIPT_KEY",
  process.env.MASTER_KEY || "MASTER_KEY"
);

Parse.serverURL = process.env.PARSE_API_ROOT || "http://parse-server:1337/parse";

const MASTER_KEY_OPTION = { useMasterKey: true }

let clients = [];

const wss = new WebSocketServer({ port: 8082 });

wss.on("connection", (ws, req) => {
  const reqUrl = new URL(req.url, `ws://${req.headers.host}`);
  const source = reqUrl.searchParams.get("source") || "Unknown";

  console.log(`Client connected to WebSocket from source: ${source}`);
  clients.push({ source, ws });

  ws.on("close", () => {
    const client = clients.find(client => client.ws === ws);
    clients = clients.filter((client) => client.ws !== ws);
    console.log("Client disconnected and process stopped");
  });
});

let outputBuffer = '';
let bufferTimeout = null;
let exploitNames = [];
let exploitData = [];

async function broadcastOutput(source, data) {

  if ( source === 'RadialOptionData' && data.includes("Module options"))
  {
    console.log("Hellooo to the future");
  }
  
  // if (source === "RadialModulesData" && commandIdentifier) {
  //   outputBuffer += data;

  //   if (bufferTimeout) clearTimeout(bufferTimeout);
  //   bufferTimeout = setTimeout(async () => {
  //     const config = parseConfig[currentCommandIndex];
  //     if (outputBuffer.includes("Name")) {
  //       try {
  //         await parseAndInsertModulesData(outputBuffer, config);
  //         console.debug("Exploits inserted into Parse successfully");
  //       } catch (error) {
  //         console.error("Error inserting exploits:", error.message);
  //       }
  //     }

  //     outputBuffer = "";
  //     currentCommandIndex = (currentCommandIndex + 1) % modulesCommandsArray.length;
  //   }, 3000);
  // }

  if (source === 'RadialOptionData' && radialOptionsDataIdentifier) {
    outputBuffer += data;
    if (bufferTimeout) clearTimeout(bufferTimeout);
        bufferTimeout = setTimeout(async () => {
            if (outputBuffer.includes("Name")) {
              const lines = outputBuffer.split("\n");
              const uniqueExploitNames = new Set(exploitNames);
              for (const line of lines) {
                const [id, name] = line.trim().split(/\s{2,}/);
                if (name && name.startsWith("exploit/")) {
                  uniqueExploitNames.add(name);
                }
                }
                exploitNames = Array.from(uniqueExploitNames);
                console.log("Parsed Exploit Names:", exploitNames);
            }
            console.log("Parsed Exploit Names length:", exploitNames.length);
            const exploitName = exploitNames[0];
            radialOptionsDataIdentifier = false;
            await processExploit(source, exploitName);
            outputBuffer = "";

          }, 5000);
  }

    const client = clients.find(client => client.source === source);
    if (client && client.ws.readyState === client.ws.OPEN) {
      // console.log("Coming into sending the data");
      client.ws.send(data);
    } else {
      console.log(`Client with source ${source} not found`);
    }
}

async function processExploit(source, exploitName) {
  try {
    console.log("```````````````````````````````````````````");
    await msfProcessFactory.runCommandForProcess(source, `use ${exploitName}`, broadcastOutput);
    await new Promise((resolve) => setTimeout(resolve, 2000));

    await msfProcessFactory.runCommandForProcess(source, `show options`, broadcastOutput);
  } catch (error) {
    console.error(`Error processing exploit ${exploitName}:`, error.message);
  }
}

async function parseAndInsertModulesData(output, config) {
  const lines = output.split("\n");
  const ansiEscapeRegex = /\x1B\[[0-9;]*[a-zA-Z]/g;
  for (const line of lines) {
    const [id, name, disclosureDate, rank, check, description] = line.trim().split(/\s{2,}/);
    if (name && disclosureDate && rank && check && description) {
      const cleanedRank = rank.replace(ansiEscapeRegex, "");

      const Exploit = Parse.Object.extend(config.className);
      const Entry = new Exploit();
      Entry.set(config.idField, id);
      Entry.set("name", name);
      Entry.set("disclosureDate", disclosureDate);
      Entry.set("rank", cleanedRank);
      Entry.set("check", check);
      Entry.set("description", description);

      // Save to Parse
      try {
        await Entry.save(null, MASTER_KEY_OPTION);
        console.debug("Successfully inserted:", name);
      } catch (error) {
        console.error("Failed to insert exploit:", name, "Error:", error.message);
      }
    }
  }
}

app.post("/start", (req, res) => {
  const { command, source } = req.body;
  try {
    const client = clients.find(client => client.source === source);
    if (!client) {
      throw new Error(`WebSocket connection not found for source: ${source}`);
    }

    if (command === "msfconsole") {
      console.log("Starting the process----");
      const message = msfProcessFactory.startProcess(source, broadcastOutput);
      res.status(200).send(message);
    } else {
      res.status(400).send("Please enter a correct command.");
    }
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/radial-options-data", async (req, res) => {
  const { source } = req.body;
  radialOptionsDataIdentifier = true;

  if (!source) {
    return res.status(400).send("No Source provided");
  }

  const process = msfProcessFactory.getProcess(source);
  if (!process) {
    return res.status(404).send("Process not found for the source");
  }

  try {
    await msfProcessFactory.runCommandForProcess(source, `show exploits`, broadcastOutput);
    res.status(200).send("Processing exploits...");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/radial-modules-data", async (req, res) => {
  const { source } = req.body;
  commandIdentifier = true;

  const modulesCommandsArray = [
    `show exploits`,
    `show payloads`,
    `show auxiliary`
  ];
  console.debug("/radial-modules-data commandsArray:", modulesCommandsArray);
  
  if (!source && !radialCommandData) {
    res.status(400).send("No Source or Command");
  }

  const process = msfProcessFactory.getProcess(source);
  if (!process){
    return res.status(404).send("Process not found for the source");
  }

  try {
    await msfProcessFactory.runCommandForProcess(source, modulesCommandsArray, broadcastOutput);
    res.status(200).send("Success");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/radial-command", async (req, res) => {
  const { source, radialCommandData } = req.body;
  console.debug("/radial-command radialCommandData:", radialCommandData);

  const selectedExploitPath = radialCommandData.selectedExploit?.split(" ")[1];
  const selectedPayloadPath = radialCommandData.selectedPayload?.split(" ")[1];
  const selectedAuxiliaryPath = radialCommandData.selectedAuxiliary?.split(" ")[1];

  console.debug("Selected Exploit Path:", selectedExploitPath);
  console.debug("Selected Payload Path:", selectedPayloadPath);
  console.debug("Selected Auxiliary Path:", selectedAuxiliaryPath);
  const { destinationIpAddr, sourceIpAddr } = radialCommandData;

  const commandsArray = [
    `use ${selectedExploitPath}`,
    `set ${selectedPayloadPath}`,
    `set RHOST ${destinationIpAddr}`,
    `set LHOST ${sourceIpAddr}`,
    `exploit`
  ];
  console.debug("/radial-command commandsArray:", commandsArray);


  if (!source && !radialCommandData) {
    res.status(400).send("No Source or Command");
  }

  const process = msfProcessFactory.getProcess(source);
  if (!process){
    return res.status(404).send("Process not found for the source");
  }

  try {
    await msfProcessFactory.runCommandForProcess(source, commandsArray, broadcastOutput);
    res.status(200).send("Success");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/command", async (req, res) => {
  const { source, command } = req.body;
  const process = msfProcessFactory.getProcess(source); 
  if (!source && !command) {
    res.status(400).send("No Source or Command");
  }

  if (!process || !process.process) {
    return res.status(400).send(`${source}: Metasploit is not running`);
  }

  try {
    res.status(200).send("Success");
    msfProcessFactory.runCommandForProcess(source, command, broadcastOutput);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/stop", (req, res) => {
  const { source } = req.body;
  const process = msfProcessFactory.getProcess(source); 
  try {
    if (!process || !process.process) {
      return res.status(400).send(`${source}: Metasploit is not running`);
    }
    commandIdentifier = false;
    currentCommandIndex = 0;

    const message = msfProcessFactory.stopProcess(source);
    res.status(200).send(message);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/processes", (req, res) => {
  const runningCount = msfProcessFactory.getRunningProcessesCount();
  res.status(200).json(runningCount);
});

const PORT = 8081;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

#!/usr/bin/env node
// ======================================================
// Wattpilot von Hand testen (lokale Websocket-Schnittstelle)
//
// Aufruf auf dem Pi, im Projektordner:
//   node tools/wattpilot-cli.js status          Zustand einmal anzeigen
//   node tools/wattpilot-cli.js watch           Änderungen live mitlesen (Strg+C beendet)
//   node tools/wattpilot-cli.js set frc 2       Wert setzen, z. B. Laden ein
//   node tools/wattpilot-cli.js get modelStatus einen Rohwert anzeigen
//
// IP:       Umgebungsvariable WATTPILOT_IP (Standard 10.0.0.102)
// Passwort: Umgebungsvariable WATTPILOT_PASSWORD, sonst wird gefragt.
//           Das Passwort wird nirgends gespeichert.
//
// Verwendet dieselbe Anmeldung wie die Wattpilot-Node in Node-RED
// (bcrypt beim Wattpilot Flex) und die Module ws + bcryptjs, die
// Node-RED für die Funktions-Nodes schon installiert hat.
// ======================================================

"use strict";

const crypto = require("crypto");
const os = require("os");
const path = require("path");
const readline = require("readline");

function load(name) {
    const paths = [
        process.cwd(),
        path.join(os.homedir(), ".node-red", "externalModules"),
        path.join(os.homedir(), ".node-red", "externalModules", "node_modules"),
        path.join(os.homedir(), ".node-red"),
        path.join(os.homedir(), ".node-red", "node_modules")
    ];
    try {
        return require(require.resolve(name, { paths }));
    } catch (e) {
        console.error("Modul '" + name + "' nicht gefunden. Installieren mit:  cd ~ && npm install " + name);
        process.exit(2);
    }
}

const WebSocket = load("ws");
const bcrypt = load("bcryptjs");

const IP = process.env.WATTPILOT_IP || "10.0.0.102";
const [cmd, key, valueText] = process.argv.slice(2);

const CAR = { 1: "kein Auto", 2: "lädt", 3: "wartet", 4: "Ladung beendet", 5: "Fehler" };
const FRC = { 0: "Neutral", 1: "Aus", 2: "Ein" };
const LMO = { 3: "Standard", 4: "Eco", 5: "Next Trip" };
const PSM = { 0: "Auto", 1: "1-phasig", 2: "3-phasig" };
const MODEL = {
    0: "lädt nicht: keine Steuerdaten",
    1: "lädt nicht: Übertemperatur",
    2: "lädt nicht: Zugangskontrolle (Karte)",
    3: "lädt: Laden ein (frc = 2)",
    4: "lädt nicht: Laden aus (frc = 1)",
    5: "lädt nicht: Zeitplan",
    6: "lädt nicht: Energielimit",
    7: "lädt: Strompreis niedrig",
    8: "lädt: Automatik-Stopp Testladung",
    9: "lädt: Automatik-Stopp, zu wenig Zeit",
    10: "lädt: Automatik-Stopp",
    11: "lädt: Automatik-Stopp ohne Uhr",
    12: "lädt: PV-Überschuss",
    13: "lädt: Rückfall go-e Standard",
    14: "lädt: Rückfall go-e Zeitplan",
    15: "lädt: Rückfall Standard",
    16: "lädt nicht: Rückfall go-e Strompreis",
    17: "lädt nicht: Rückfall Strompreis",
    18: "lädt nicht: Rückfall Automatik-Stopp",
    19: "lädt: Auto-Kompatibilität (Keep-Alive)",
    20: "lädt: Ladepause nicht erlaubt",
    22: "lädt nicht: Ausstecken simulieren",
    23: "lädt nicht: Phasenumschaltung",
    24: "lädt nicht: Mindestpause"
};

const WATCH = ["car", "modelStatus", "frc", "lmo", "amp", "psm", "alw", "err", "pnp", "fup", "su"];

function usage() {
    console.log([
        "Aufruf:",
        "  node tools/wattpilot-cli.js status",
        "  node tools/wattpilot-cli.js watch",
        "  node tools/wattpilot-cli.js set <schlüssel> <wert>   z. B. set frc 2",
        "  node tools/wattpilot-cli.js get <schlüssel>          z. B. get modelStatus",
        "",
        "Wichtige Schlüssel:",
        "  frc  0 Neutral, 1 Laden aus, 2 Laden ein",
        "  lmo  3 Standard, 4 Eco, 5 Next Trip",
        "  amp  Ladestrom in A (6 bis 16)",
        "  psm  0 Auto, 1 1-phasig, 2 3-phasig"
    ].join("\n"));
}

if (!cmd || !["status", "watch", "set", "get"].includes(cmd) ||
    (cmd === "set" && (key === undefined || valueText === undefined)) ||
    (cmd === "get" && key === undefined)) {
    usage();
    process.exit(1);
}

// ------------------------------------------------------
// Passwort
// ------------------------------------------------------

function askPassword() {
    if (process.env.WATTPILOT_PASSWORD) return Promise.resolve(process.env.WATTPILOT_PASSWORD);
    return new Promise(resolve => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
        rl.stdoutMuted = false;
        rl._writeToOutput = function (s) {
            if (rl.stdoutMuted) rl.output.write(s.includes("\n") ? "\n" : "");
            else rl.output.write(s);
        };
        rl.question("Wattpilot-Passwort: ", pw => { rl.close(); resolve(pw); });
        rl.stdoutMuted = true;
    });
}

const sha256hex = t => crypto.createHash("sha256").update(t, "utf8").digest("hex");

function hashPassword(serial, password, algorithm) {
    if (algorithm === "bcrypt") {
        const b = new Array(16).fill(0);
        const s = String(serial);
        const off = 16 - s.length;
        for (let i = 0; i < s.length; i++) if (off + i >= 0) b[off + i] = s.charCodeAt(i) - 48;
        const salt = "$2a$08$" + bcrypt.encodeBase64(b, 16);
        return bcrypt.hashSync(sha256hex(password), salt).substring(salt.length);
    }
    return crypto.pbkdf2Sync(password, String(serial), 100000, 256, "sha512").toString("base64").substring(0, 32);
}

// ------------------------------------------------------
// Anzeige
// ------------------------------------------------------

function label(k, v) {
    const map = { car: CAR, frc: FRC, lmo: LMO, psm: PSM, modelStatus: MODEL }[k];
    return map && map[v] !== undefined ? v + " (" + map[v] + ")" : JSON.stringify(v);
}

function printStatus(s) {
    const nrg = Array.isArray(s.nrg) ? s.nrg : [];
    const lines = [
        ["Auto (car)", label("car", s.car)],
        ["Grund (modelStatus)", label("modelStatus", s.modelStatus)],
        ["Laden ein/aus (frc)", label("frc", s.frc)],
        ["Lademodus (lmo)", label("lmo", s.lmo)],
        ["Ladestrom (amp)", s.amp + " A"],
        ["Phasen (psm)", label("psm", s.psm)],
        ["Laden erlaubt (alw)", JSON.stringify(s.alw)],
        ["Fehler (err)", JSON.stringify(s.err)],
        ["Leistung", (nrg[11] !== undefined ? Math.round(nrg[11]) + " W" : "—") +
            (nrg.length ? "  (L1 " + nrg[4] + " A, L2 " + nrg[5] + " A, L3 " + nrg[6] + " A)" : "")],
        ["PV-Überschuss (fup)", JSON.stringify(s.fup)],
        ["Ausstecken simulieren (su)", JSON.stringify(s.su)]
    ];
    for (const [a, b] of lines) console.log(a.padEnd(28) + b);
}

const stamp = () => new Date().toLocaleTimeString("de-AT");

// ------------------------------------------------------
// Ablauf
// ------------------------------------------------------

(async () => {
    const password = await askPassword();
    const ws = new WebSocket("ws://" + IP + "/ws", { handshakeTimeout: 10000 });

    const status = {};
    let serial = null, devicetype = null, hashed = null, secured = true;
    let requestId = 0, statusComplete = false, done = false;

    const finish = code => { if (done) return; done = true; try { ws.close(); } catch (e) { } setTimeout(() => process.exit(code), 200); };
    const timeout = setTimeout(() => { console.error("Zeitüberschreitung: keine vollständige Antwort vom Wattpilot."); finish(3); }, cmd === "watch" ? 30000 : 20000);

    function sendSet(k, v) {
        const setValue = { requestId, key: k, value: v, type: "setValue" };
        let msg = setValue;
        if (secured) {
            const data = JSON.stringify(setValue);
            const hmac = crypto.createHmac("sha256", Buffer.from(hashed, "utf8")).update(data, "utf8").digest("hex");
            msg = { type: "securedMsg", data, requestId: requestId + "sm", hmac };
        }
        requestId++;
        ws.send(JSON.stringify(msg));
    }

    function onComplete() {
        clearTimeout(timeout);
        if (cmd === "status") { printStatus(status); finish(0); }
        else if (cmd === "get") { console.log(key + " = " + label(key, status[key])); finish(0); }
        else if (cmd === "watch") { printStatus(status); console.log("\n" + stamp() + "  läuft, Änderungen erscheinen hier (Strg+C beendet) …"); }
        else if (cmd === "set") {
            let v;
            try { v = JSON.parse(valueText); } catch (e) { v = valueText; }
            console.log("vorher:  " + key + " = " + label(key, status[key]));
            sendSet(key, v);
            setTimeout(() => { console.error("Keine Antwort auf den Befehl."); finish(4); }, 10000);
        }
    }

    ws.on("message", data => {
        let m;
        try { m = JSON.parse(data.toString()); } catch (e) { return; }

        if (m.type === "hello") {
            serial = m.serial; devicetype = m.devicetype; secured = m.secured !== false;
            console.log("Verbunden mit " + IP + ": " + devicetype + ", Seriennummer " + serial + ", Firmware " + m.version);
        }
        else if (m.type === "authRequired") {
            const algorithm = m.hash || (devicetype === "wattpilot_flex" ? "bcrypt" : "pbkdf2");
            hashed = hashPassword(serial, password, algorithm);
            const token3 = crypto.randomBytes(16).toString("hex");
            const hash1 = sha256hex(m.token1 + hashed);
            ws.send(JSON.stringify({ type: "auth", token3, hash: sha256hex(token3 + m.token2 + hash1) }));
        }
        else if (m.type === "authSuccess") {
            requestId = 0;
            console.log("Anmeldung ok\n");
        }
        else if (m.type === "authError") {
            console.error("Anmeldung fehlgeschlagen: Passwort falsch?");
            finish(5);
        }
        else if (m.type === "fullStatus" || m.type === "deltaStatus") {
            const changes = m.type === "deltaStatus" && statusComplete
                ? WATCH.filter(k => k in (m.status || {}) && JSON.stringify(m.status[k]) !== JSON.stringify(status[k]))
                : [];
            Object.assign(status, m.status || {});
            if (cmd === "watch" && changes.length) {
                console.log(stamp() + "  " + changes.map(k => k + " = " + label(k, status[k])).join(",  "));
            }
            if (cmd === "watch" && statusComplete && m.status && Array.isArray(m.status.nrg)) {
                const p = Math.round(m.status.nrg[11] || 0);
                if (Math.abs(p - (status._lastP || 0)) >= 300) {
                    console.log(stamp() + "  Leistung " + p + " W");
                    status._lastP = p;
                }
            }
            if (m.type === "fullStatus" && m.partial === false && !statusComplete) {
                statusComplete = true;
                onComplete();
            }
        }
        else if (m.type === "response" && cmd === "set") {
            if (m.success === false) {
                console.error("Wattpilot hat den Befehl abgelehnt: " + (m.message || JSON.stringify(m)));
                finish(6);
            } else {
                if (m.status) Object.assign(status, m.status);
                console.log("nachher: " + key + " = " + label(key, status[key]));
                setTimeout(() => { console.log(""); printStatus(status); finish(0); }, 3000);
            }
        }
    });

    ws.on("error", e => { console.error("Verbindungsfehler: " + e.message); finish(7); });
    ws.on("close", () => { if (!done) { console.error("Verbindung getrennt."); finish(8); } });
    process.on("SIGINT", () => { console.log("\nbeendet"); finish(0); });
})();

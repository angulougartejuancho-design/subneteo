"use strict";

const HISTORY_KEY = "netscope.history";
const HISTORY_LIMIT = 12;

const state = {
  family: "ipv4",
  lastResult: null,
  history: loadHistory()
};

const elements = {
  validationBadge: document.getElementById("validationBadge"),
  ipv4Tab: document.getElementById("ipv4Tab"),
  ipv6Tab: document.getElementById("ipv6Tab"),
  form: document.getElementById("calculatorForm"),
  addressInput: document.getElementById("addressInput"),
  prefixInput: document.getElementById("prefixInput"),
  prefixSlider: document.getElementById("prefixSlider"),
  targetPrefix: document.getElementById("targetPrefix"),
  copyReport: document.getElementById("copyReport"),
  copyAddress: document.getElementById("copyAddress"),
  resetAll: document.getElementById("resetAll"),
  clearHistory: document.getElementById("clearHistory"),
  historyList: document.getElementById("historyList"),
  summaryGrid: document.getElementById("summaryGrid"),
  detailsTable: document.getElementById("detailsTable"),
  bitViewer: document.getElementById("bitViewer"),
  bitsTitle: document.getElementById("bitsTitle"),
  analysisSubtitle: document.getElementById("analysisSubtitle"),
  addressFamilyTag: document.getElementById("addressFamilyTag"),
  visualNetwork: document.getElementById("visualNetwork"),
  visualScope: document.getElementById("visualScope"),
  plannerMeta: document.getElementById("plannerMeta"),
  subnetRows: document.getElementById("subnetRows"),
  toast: document.getElementById("toast")
};

const MAX_IPV6 = (1n << 128n) - 1n;

function clamp(value, min, max) {
  const number = Number(value);
  if (Number.isNaN(number)) return min;
  return Math.min(max, Math.max(min, number));
}

function formatBigInt(value) {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function loadHistory() {
  try {
    const stored = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    if (!Array.isArray(stored)) return [];
    return stored
      .filter((item) => item && item.id && item.family && item.input && item.cidr)
      .slice(0, HISTORY_LIMIT);
  } catch (error) {
    return [];
  }
}

function saveHistory() {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history));
  } catch (error) {
    return;
  }
}

function setStatus(message, ok) {
  elements.validationBadge.textContent = message;
  elements.validationBadge.classList.toggle("status-ok", ok);
  elements.validationBadge.classList.toggle("status-error", !ok);
}

function toast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => {
    elements.toast.classList.remove("show");
  }, 2200);
}

function parseAddressAndPrefix(raw, fallbackPrefix) {
  const trimmed = raw.trim();
  const slashIndex = trimmed.lastIndexOf("/");
  if (slashIndex === -1) {
    return { address: trimmed, prefix: Number(fallbackPrefix) };
  }

  return {
    address: trimmed.slice(0, slashIndex).trim(),
    prefix: Number(trimmed.slice(slashIndex + 1).trim())
  };
}

function parseIPv4Address(address) {
  const parts = address.split(".");
  if (parts.length !== 4) throw new Error("IPv4 requires four octets.");

  return parts.reduce((total, part) => {
    if (!/^\d{1,3}$/.test(part)) throw new Error("IPv4 octets must be numeric.");
    const octet = Number(part);
    if (octet < 0 || octet > 255) throw new Error("IPv4 octets must be between 0 and 255.");
    return ((total * 256) + octet) >>> 0;
  }, 0) >>> 0;
}

function intToIPv4(value) {
  const number = Number(value) >>> 0;
  return [
    (number >>> 24) & 255,
    (number >>> 16) & 255,
    (number >>> 8) & 255,
    number & 255
  ].join(".");
}

function ipv4Mask(prefix) {
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function ipv4Class(ip) {
  const first = (ip >>> 24) & 255;
  if (first <= 127) return "Class A";
  if (first <= 191) return "Class B";
  if (first <= 223) return "Class C";
  if (first <= 239) return "Class D";
  return "Class E";
}

function ipv4Scope(ip) {
  const first = (ip >>> 24) & 255;
  const second = (ip >>> 16) & 255;
  if (first === 10) return "Private network";
  if (first === 172 && second >= 16 && second <= 31) return "Private network";
  if (first === 192 && second === 168) return "Private network";
  if (first === 127) return "Loopback";
  if (first === 169 && second === 254) return "Link-local";
  if (first >= 224 && first <= 239) return "Multicast";
  if (first >= 240) return "Reserved";
  if (first === 0) return "Current network";
  return "Public network";
}

function ipv4Binary(ip) {
  return intToIPv4(ip)
    .split(".")
    .map((part) => Number(part).toString(2).padStart(8, "0"));
}

function analyzeIPv4() {
  const parsed = parseAddressAndPrefix(elements.addressInput.value, elements.prefixInput.value);
  const prefix = clamp(parsed.prefix, 0, 32);
  if (!Number.isInteger(parsed.prefix) || parsed.prefix < 0 || parsed.prefix > 32) {
    throw new Error("IPv4 prefix must be between 0 and 32.");
  }

  const ip = parseIPv4Address(parsed.address);
  const mask = ipv4Mask(prefix);
  const wildcard = (~mask) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const hostBits = 32 - prefix;
  const totalAddresses = 1n << BigInt(hostBits);
  const usableHosts = prefix === 32 ? 1n : prefix === 31 ? 2n : totalAddresses - 2n;
  const firstHost = prefix < 31 ? (network + 1) >>> 0 : network;
  const lastHost = prefix < 31 ? (broadcast - 1) >>> 0 : broadcast;
  const blockSize = Math.pow(2, hostBits);

  return {
    family: "ipv4",
    address: intToIPv4(ip),
    cidr: `${intToIPv4(network)}/${prefix}`,
    prefix,
    ip,
    network,
    broadcast,
    firstHost,
    lastHost,
    mask,
    wildcard,
    totalAddresses,
    usableHosts,
    scope: ipv4Scope(ip),
    className: ipv4Class(ip),
    hostBits,
    blockSize
  };
}

function convertEmbeddedIPv4(address) {
  if (!address.includes(".")) return address;
  const lastColon = address.lastIndexOf(":");
  if (lastColon === -1) throw new Error("Invalid IPv6 embedded IPv4 address.");
  const ipv4Part = address.slice(lastColon + 1);
  const ipv4Value = parseIPv4Address(ipv4Part);
  const high = ((ipv4Value >>> 16) & 0xffff).toString(16);
  const low = (ipv4Value & 0xffff).toString(16);
  return `${address.slice(0, lastColon)}:${high}:${low}`;
}

function parseIPv6Groups(address) {
  const normalized = convertEmbeddedIPv4(address.toLowerCase().split("%")[0]);
  if (!normalized) throw new Error("IPv6 address is required.");
  if ((normalized.match(/::/g) || []).length > 1) throw new Error("IPv6 can contain only one double colon.");

  const hasCompression = normalized.includes("::");
  const sections = normalized.split("::");
  const head = sections[0] ? sections[0].split(":") : [];
  const tail = sections[1] ? sections[1].split(":") : [];
  const allParts = hasCompression ? [...head, ...tail] : normalized.split(":");

  allParts.forEach((part) => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) throw new Error("IPv6 groups must be hexadecimal.");
  });

  if (!hasCompression && allParts.length !== 8) throw new Error("IPv6 requires eight groups or :: compression.");

  const missing = 8 - head.length - tail.length;
  if (hasCompression && missing < 1) throw new Error("IPv6 compression expands beyond eight groups.");

  const groups = hasCompression
    ? [...head, ...Array(missing).fill("0"), ...tail]
    : allParts;

  if (groups.length !== 8) throw new Error("IPv6 must resolve to eight groups.");
  return groups.map((part) => Number.parseInt(part, 16));
}

function groupsToBigInt(groups) {
  return groups.reduce((total, group) => (total << 16n) + BigInt(group), 0n);
}

function bigIntToGroups(value) {
  const groups = [];
  for (let shift = 112n; shift >= 0n; shift -= 16n) {
    groups.push(Number((value >> shift) & 0xffffn));
  }
  return groups;
}

function expandIPv6(groups) {
  return groups.map((group) => group.toString(16).padStart(4, "0")).join(":");
}

function compressIPv6(groups) {
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;

  groups.forEach((group, index) => {
    if (group === 0) {
      if (currentStart === -1) currentStart = index;
      currentLength += 1;
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
    } else {
      currentStart = -1;
      currentLength = 0;
    }
  });

  if (bestLength < 2) return groups.map((group) => group.toString(16)).join(":");

  const parts = [];
  for (let index = 0; index < groups.length; index += 1) {
    if (index === bestStart) {
      parts.push("");
      index += bestLength - 1;
      if (index === groups.length - 1) parts.push("");
    } else {
      parts.push(groups[index].toString(16));
    }
  }

  if (bestStart === 0) parts.unshift("");
  return parts.join(":").replace(/:{3,}/, "::");
}

function bigIntToIPv6(value, compressed = true) {
  const groups = bigIntToGroups(value);
  return compressed ? compressIPv6(groups) : expandIPv6(groups);
}

function ipv6Scope(value) {
  if (value === 0n) return "Unspecified";
  if (value === 1n) return "Loopback";
  if ((value >> 121n) === 0b1111110n) return "Unique local";
  if ((value >> 118n) === 0b1111111010n) return "Link-local";
  if ((value >> 120n) === 0xffn) return "Multicast";
  if ((value >> 96n) === 0x20010db8n) return "Documentation";
  if ((value >> 112n) === 0x2002n) return "6to4";
  if ((value >> 125n) === 0b001n) return "Global unicast";
  return "Reserved or special";
}

function ipv6Reverse(groups) {
  return expandIPv6(groups).replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa";
}

function analyzeIPv6() {
  const parsed = parseAddressAndPrefix(elements.addressInput.value, elements.prefixInput.value);
  const prefix = clamp(parsed.prefix, 0, 128);
  if (!Number.isInteger(parsed.prefix) || parsed.prefix < 0 || parsed.prefix > 128) {
    throw new Error("IPv6 prefix must be between 0 and 128.");
  }

  const groups = parseIPv6Groups(parsed.address);
  const value = groupsToBigInt(groups);
  const hostBits = 128 - prefix;
  const mask = hostBits === 128 ? 0n : (MAX_IPV6 << BigInt(hostBits)) & MAX_IPV6;
  const network = value & mask;
  const last = network + ((1n << BigInt(hostBits)) - 1n);

  return {
    family: "ipv6",
    address: bigIntToIPv6(value),
    expanded: expandIPv6(groups),
    cidr: `${bigIntToIPv6(network)}/${prefix}`,
    prefix,
    value,
    network,
    first: network,
    last,
    totalAddresses: 1n << BigInt(hostBits),
    hostBits,
    groups,
    networkGroups: bigIntToGroups(network),
    scope: ipv6Scope(value),
    reverse: ipv6Reverse(groups)
  };
}

function renderMetric(label, value, accent = false) {
  return `
    <article class="metric-card ${accent ? "accent" : ""}">
      <span>${label}</span>
      <strong>${value}</strong>
    </article>
  `;
}

function renderDetails(rows) {
  elements.detailsTable.innerHTML = rows.map(([label, value]) => `
    <div class="detail-row">
      <span>${label}</span>
      <strong>${value}</strong>
    </div>
  `).join("");
}

function renderIPv4Bits(result) {
  const octets = ipv4Binary(result.ip);
  let bitIndex = 0;
  elements.bitViewer.innerHTML = octets.map((octet, octetIndex) => {
    const cells = octet.split("").map((bit) => {
      const zone = bitIndex < result.prefix ? "network" : "host";
      bitIndex += 1;
      return `<span class="bit-cell ${zone}">${bit}</span>`;
    }).join("");
    return `
      <div class="octet-row">
        <div class="bit-label"><span>Octet ${octetIndex + 1}</span><span>${Number.parseInt(octet, 2)}</span></div>
        <div class="bit-strip ipv4-bits">${cells}</div>
      </div>
    `;
  }).join("");
}

function renderIPv6Bits(result) {
  elements.bitViewer.innerHTML = result.networkGroups.map((group, index) => {
    const hextetStart = index * 16;
    const groupText = group.toString(16).padStart(4, "0");
    const cells = groupText.split("").map((hex, charIndex) => {
      const zone = hextetStart + (charIndex * 4) < result.prefix ? "network" : "host";
      return `<span class="bit-cell ${zone}">${hex}</span>`;
    }).join("");
    return `
      <div class="hextet-row">
        <div class="bit-label"><span>Group ${index + 1}</span><span>${groupText}</span></div>
        <div class="bit-strip ipv6-bits">${cells}</div>
      </div>
    `;
  }).join("");
}

function renderIPv4(result) {
  elements.analysisSubtitle.textContent = "IPv4 network profile";
  elements.addressFamilyTag.textContent = "IPv4";
  elements.bitsTitle.textContent = "Binary View";
  elements.visualNetwork.textContent = result.cidr;
  elements.visualScope.textContent = result.scope;

  elements.summaryGrid.innerHTML = [
    renderMetric("Network", result.cidr, true),
    renderMetric("Usable hosts", formatBigInt(result.usableHosts)),
    renderMetric("Broadcast", intToIPv4(result.broadcast)),
    renderMetric("Subnet mask", intToIPv4(result.mask))
  ].join("");

  renderDetails([
    ["Address", result.address],
    ["First host", intToIPv4(result.firstHost)],
    ["Last host", intToIPv4(result.lastHost)],
    ["Wildcard mask", intToIPv4(result.wildcard)],
    ["Total addresses", formatBigInt(result.totalAddresses)],
    ["Host bits", result.hostBits],
    ["Class", result.className],
    ["Scope", result.scope]
  ]);

  renderIPv4Bits(result);
  renderIPv4Subnets(result);
}

function renderIPv6(result) {
  elements.analysisSubtitle.textContent = "IPv6 network profile";
  elements.addressFamilyTag.textContent = "IPv6";
  elements.bitsTitle.textContent = "Hex Group View";
  elements.visualNetwork.textContent = result.cidr;
  elements.visualScope.textContent = result.scope;

  elements.summaryGrid.innerHTML = [
    renderMetric("Network", result.cidr, true),
    renderMetric("Compressed", result.address),
    renderMetric("First address", bigIntToIPv6(result.first)),
    renderMetric("Last address", bigIntToIPv6(result.last))
  ].join("");

  renderDetails([
    ["Expanded address", result.expanded],
    ["Prefix length", `/${result.prefix}`],
    ["Host bits", result.hostBits],
    ["Total addresses", formatBigInt(result.totalAddresses)],
    ["Scope", result.scope],
    ["Reverse DNS", result.reverse]
  ]);

  renderIPv6Bits(result);
  renderIPv6Subnets(result);
}

function renderIPv4Subnets(result) {
  const target = clamp(elements.targetPrefix.value, result.prefix, 32);
  elements.targetPrefix.value = target;
  elements.targetPrefix.min = result.prefix;
  elements.targetPrefix.max = 32;

  const subnetCount = 1n << BigInt(target - result.prefix);
  const step = Math.pow(2, 32 - target);
  const usable = target === 32 ? 1n : target === 31 ? 2n : (1n << BigInt(32 - target)) - 2n;
  const rowsToRender = Number(subnetCount > 64n ? 64n : subnetCount);

  elements.plannerMeta.textContent = `${formatBigInt(subnetCount)} subnet${subnetCount === 1n ? "" : "s"} at /${target}`;
  elements.subnetRows.innerHTML = Array.from({ length: rowsToRender }, (_, index) => {
    const network = (result.network + (index * step)) >>> 0;
    const broadcast = (network + step - 1) >>> 0;
    const first = target < 31 ? (network + 1) >>> 0 : network;
    const last = target < 31 ? (broadcast - 1) >>> 0 : broadcast;
    return `
      <tr>
        <td>${intToIPv4(network)}/${target}</td>
        <td>${intToIPv4(first)}</td>
        <td>${intToIPv4(last)}</td>
        <td>${formatBigInt(usable)}</td>
      </tr>
    `;
  }).join("");
}

function renderIPv6Subnets(result) {
  const target = clamp(elements.targetPrefix.value, result.prefix, 128);
  elements.targetPrefix.value = target;
  elements.targetPrefix.min = result.prefix;
  elements.targetPrefix.max = 128;

  const subnetCount = 1n << BigInt(target - result.prefix);
  const step = 1n << BigInt(128 - target);
  const rowsToRender = Number(subnetCount > 32n ? 32n : subnetCount);

  elements.plannerMeta.textContent = `${formatBigInt(subnetCount)} subnet${subnetCount === 1n ? "" : "s"} at /${target}`;
  elements.subnetRows.innerHTML = Array.from({ length: rowsToRender }, (_, index) => {
    const network = result.network + (BigInt(index) * step);
    const last = network + step - 1n;
    return `
      <tr>
        <td>${bigIntToIPv6(network)}/${target}</td>
        <td>${bigIntToIPv6(network)}</td>
        <td>${bigIntToIPv6(last)}</td>
        <td>${formatBigInt(step)}</td>
      </tr>
    `;
  }).join("");
}

function historyRecord(result) {
  const detail = result.family === "ipv4"
    ? `${formatBigInt(result.usableHosts)} usable hosts`
    : `${formatBigInt(result.totalAddresses)} addresses`;

  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    family: result.family,
    input: `${result.address}/${result.prefix}`,
    prefix: result.prefix,
    cidr: result.cidr,
    scope: result.scope,
    detail
  };
}

function renderHistory() {
  elements.clearHistory.disabled = state.history.length === 0;

  if (state.history.length === 0) {
    elements.historyList.innerHTML = `<div class="history-empty">No saved calculations.</div>`;
    return;
  }

  elements.historyList.innerHTML = state.history.map((item) => `
    <button class="history-item" type="button" data-history-id="${escapeHtml(item.id)}">
      <strong>${escapeHtml(item.cidr)}</strong>
      <span>${escapeHtml(item.family.toUpperCase())} - ${escapeHtml(item.scope)} - ${escapeHtml(item.detail)}</span>
    </button>
  `).join("");
}

function addHistory(result) {
  const record = historyRecord(result);
  state.history = [
    record,
    ...state.history.filter((item) => item.family !== record.family || item.cidr !== record.cidr)
  ].slice(0, HISTORY_LIMIT);
  saveHistory();
  renderHistory();
}

function restoreHistoryItem(id) {
  const item = state.history.find((entry) => entry.id === id);
  if (!item) return;

  setFamily(item.family);
  elements.addressInput.value = item.input;
  elements.prefixInput.value = item.prefix;
  elements.prefixSlider.value = item.prefix;
  calculate();
  toast("History item loaded");
}

function clearHistory() {
  if (state.history.length === 0) return;
  state.history = [];
  saveHistory();
  renderHistory();
  toast("History cleared");
}

function calculate(saveToHistory = false) {
  try {
    const result = state.family === "ipv4" ? analyzeIPv4() : analyzeIPv6();
    state.lastResult = result;
    elements.prefixInput.value = result.prefix;
    elements.prefixSlider.value = result.prefix;
    if (result.family === "ipv4") renderIPv4(result);
    if (result.family === "ipv6") renderIPv6(result);
    if (saveToHistory) addHistory(result);
    setStatus("Valid", true);
  } catch (error) {
    state.lastResult = null;
    setStatus("Invalid", false);
    elements.analysisSubtitle.textContent = error.message;
    elements.summaryGrid.innerHTML = renderMetric("Validation", error.message, true);
    elements.detailsTable.innerHTML = "";
    elements.bitViewer.innerHTML = "";
    elements.subnetRows.innerHTML = "";
    elements.plannerMeta.textContent = "Waiting for a valid network";
  }
}

function setFamily(family) {
  state.family = family;
  const isIPv4 = family === "ipv4";
  elements.ipv4Tab.classList.toggle("active", isIPv4);
  elements.ipv6Tab.classList.toggle("active", !isIPv4);
  elements.ipv4Tab.setAttribute("aria-selected", String(isIPv4));
  elements.ipv6Tab.setAttribute("aria-selected", String(!isIPv4));
  elements.prefixInput.max = isIPv4 ? "32" : "128";
  elements.prefixSlider.max = isIPv4 ? "32" : "128";
  elements.addressInput.value = isIPv4 ? "192.168.10.34/24" : "2001:db8:42:9::21/64";
  elements.prefixInput.value = isIPv4 ? "24" : "64";
  elements.prefixSlider.value = isIPv4 ? "24" : "64";
  elements.targetPrefix.value = isIPv4 ? "26" : "68";
  document.querySelectorAll(".chip").forEach((chip) => chip.classList.remove("active"));
  calculate();
}

async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    toast(message);
  }
}

function reportText() {
  if (!state.lastResult) return "";
  const result = state.lastResult;
  if (result.family === "ipv4") {
    return [
      "NetScope IPv4 Report",
      `Address: ${result.address}`,
      `Network: ${result.cidr}`,
      `Mask: ${intToIPv4(result.mask)}`,
      `Wildcard: ${intToIPv4(result.wildcard)}`,
      `First host: ${intToIPv4(result.firstHost)}`,
      `Last host: ${intToIPv4(result.lastHost)}`,
      `Broadcast: ${intToIPv4(result.broadcast)}`,
      `Usable hosts: ${formatBigInt(result.usableHosts)}`,
      `Scope: ${result.scope}`
    ].join("\n");
  }

  return [
    "NetScope IPv6 Report",
    `Address: ${result.address}`,
    `Expanded: ${result.expanded}`,
    `Network: ${result.cidr}`,
    `First address: ${bigIntToIPv6(result.first)}`,
    `Last address: ${bigIntToIPv6(result.last)}`,
    `Total addresses: ${formatBigInt(result.totalAddresses)}`,
    `Scope: ${result.scope}`,
    `Reverse DNS: ${result.reverse}`
  ].join("\n");
}

elements.form.addEventListener("submit", (event) => {
  event.preventDefault();
  calculate(true);
});

elements.addressInput.addEventListener("input", () => {
  const parsed = parseAddressAndPrefix(elements.addressInput.value, elements.prefixInput.value);
  if (!Number.isNaN(parsed.prefix)) {
    elements.prefixInput.value = parsed.prefix;
    elements.prefixSlider.value = parsed.prefix;
  }
  calculate();
});

elements.prefixInput.addEventListener("input", () => {
  elements.prefixSlider.value = elements.prefixInput.value;
  calculate();
});

elements.prefixSlider.addEventListener("input", () => {
  elements.prefixInput.value = elements.prefixSlider.value;
  calculate();
});

elements.targetPrefix.addEventListener("input", () => {
  if (!state.lastResult) return;
  if (state.lastResult.family === "ipv4") renderIPv4Subnets(state.lastResult);
  if (state.lastResult.family === "ipv6") renderIPv6Subnets(state.lastResult);
});

elements.ipv4Tab.addEventListener("click", () => setFamily("ipv4"));
elements.ipv6Tab.addEventListener("click", () => setFamily("ipv6"));
elements.clearHistory.addEventListener("click", clearHistory);
elements.historyList.addEventListener("click", (event) => {
  const item = event.target.closest("[data-history-id]");
  if (!item) return;
  restoreHistoryItem(item.dataset.historyId);
});

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach((item) => item.classList.remove("active"));
    elements.addressInput.value = chip.dataset.example;
    setFamily(chip.dataset.example.includes(":") ? "ipv6" : "ipv4");
    chip.classList.add("active");
    elements.addressInput.value = chip.dataset.example;
    calculate();
  });
});

elements.copyReport.addEventListener("click", () => copyText(reportText(), "Report copied"));
elements.copyAddress.addEventListener("click", () => {
  if (!state.lastResult) return;
  copyText(state.lastResult.cidr, "Network copied");
});

elements.resetAll.addEventListener("click", () => setFamily("ipv4"));

renderHistory();
calculate();

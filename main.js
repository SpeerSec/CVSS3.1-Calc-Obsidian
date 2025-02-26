/**
 * Obsidian CVSS 3.1 Calculator Plugin
 * Adds a sidebar to your obsidian notes to calculate basic cvss 3.1 using equations from NVD.
 * Forgive my debugging logs...
 */

const { Plugin, ItemView, WorkspaceLeaf } = require("obsidian");

class CVSSCalculatorPlugin extends Plugin {
  async onload() {
    console.log("CVSS Calculator Plugin loaded");

    this.addRibbonIcon("calculator", "CVSS Calculator", () => {
      this.activateView();
    });

    this.registerView(
      "cvss-calculator-view",
      (leaf) => new CVSSCalculatorView(leaf)
    );
  }

  async activateView() {
    let { workspace } = this.app;
    let leaf = workspace.getRightLeaf(false);
    await leaf.setViewState({
      type: "cvss-calculator-view",
      active: true,
    });
    workspace.revealLeaf(leaf);
  }

  onunload() {
    console.log("CVSS Calculator Plugin unloaded");
  }
}

class CVSSCalculatorView extends ItemView {
  constructor(leaf) {
    super(leaf);
  }

  getViewType() {
    return "cvss-calculator-view";
  }

  getDisplayText() {
    return "CVSS 3.1 Calculator";
  }

  async onOpen() {
    let container = this.containerEl.children[1];
    container.empty();
    container.createEl("h2", { text: "CVSS 3.1 Calculator", cls: "cvss-header" });
    container.createEl("h6", { text: "v0.1.0 By Speer", cls :"cvss-header"});
    
    // Create input fields
    let form = container.createEl("div", { cls: "cvss-form" });
    const metrics = [
      { name: "Attack Vector", key: "AV", values: ["Network", "Adjacent", "Local", "Physical"] },
      { name: "Attack Complexity", key: "AC", values: ["Low", "High"] },
      { name: "Privileges Required", key: "PR", values: ["None", "Low", "High"] },
      { name: "User Interaction", key: "UI", values: ["None", "Required"] },
      { name: "Scope", key: "S", values: ["Unchanged", "Changed"] },
      { name: "Confidentiality", key: "C", values: ["None", "Low", "High"] },
      { name: "Integrity", key: "I", values: ["None", "Low", "High"] },
      { name: "Availability", key: "A", values: ["None", "Low", "High"] }
    ];
    
    let selections = {};
    
    metrics.forEach(metric => {
      let fieldWrapper = form.createEl("div", { cls: "cvss-field" });
      fieldWrapper.style.marginBottom = "15px";
      
      let label = fieldWrapper.createEl("label", { text: metric.name, cls: "cvss-label" });
      label.style.display = "block";
      label.style.marginBottom = "8px";
      
      let buttonGroup = fieldWrapper.createEl("div", { cls: "cvss-button-group" });
      selections[metric.key] = metric.values[0];
      
      metric.values.forEach(value => {
        let radioWrapper = buttonGroup.createEl("div", { cls: "cvss-radio-wrapper" });
        let radio = radioWrapper.createEl("input", { type: "radio", name: metric.key, value: value, cls: "cvss-radio" });
        radio.setAttribute("name", metric.key); // Ensure only one radio button is selectable per metric
        let radioLabel = radioWrapper.createEl("label", { text: value, cls: "cvss-radio-label" });
        radioLabel.setAttribute("for", value + metric.key); 
        radio.setAttribute("id", value + metric.key);
        
        radio.addEventListener("change", () => {
          selections[metric.key] = value;
          updateScore();
        });
        
        radioWrapper.appendChild(radio);
        radioWrapper.appendChild(radioLabel);
        buttonGroup.appendChild(radioWrapper);
      });
      
      fieldWrapper.appendChild(buttonGroup);
      form.appendChild(fieldWrapper);
    });
    
    let scoreEl = container.createEl("div", { text: "N/A", cls: "cvss-score" });
    scoreEl.style.marginTop = "22px";
    scoreEl.style.fontSize = "16px";
    scoreEl.style.fontWeight = "bold";
    scoreEl.style.cursor = "pointer";
    scoreEl.style.userSelect = "all";
    scoreEl.style.color = "green";
    
    let vectorEl = container.createEl("div", { text: "N/A", cls: "cvss-vector" });
    vectorEl.style.marginTop = "8px";
    vectorEl.style.fontSize = "14px";
    vectorEl.style.cursor = "pointer";
    vectorEl.style.userSelect = "all";
    vectorEl.style.color = "yellow"
    
    function updateScore() {
      let score = calculateCVSS(selections);
      let vector = generateCVSSVector(selections);
      scoreEl.textContent = score;
      vectorEl.textContent = vector.replace("CVSS:3.1/", "");
    }
  }
}

function calculateCVSS(selections) {
  try {
    const AV = { "Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2 }[selections["AV"]];
    const AC = { "Low": 0.77, "High": 0.44 }[selections["AC"]];
    const PR = { "None": 0.85, "Low": 0.62, "High": 0.27 }[selections["PR"]];
    const UI = { "None": 0.85, "Required": 0.62 }[selections["UI"]];
    const C = { "None": 0.0, "Low": 0.22, "High": 0.56 }[selections["C"]];
    const I = { "None": 0.0, "Low": 0.22, "High": 0.56 }[selections["I"]];
    const A = { "None": 0.0, "Low": 0.22, "High": 0.56 }[selections["A"]];
    
    const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));
    const Impact = 6.42 * ISS;
    const Exploitability = 8.22 * AV * AC * PR * UI;
    return Math.ceil((Impact + Exploitability) * 10) / 10;
  } catch (error) {
    return "Error: Invalid selection";
  }
}

function generateCVSSVector(selections) {
  return `AV:${selections["AV"].charAt(0)}/AC:${selections["AC"].charAt(0)}/PR:${selections["PR"].charAt(0)}/UI:${selections["UI"].charAt(0)}/S:${selections["S"].charAt(0)}/C:${selections["C"].charAt(0)}/I:${selections["I"].charAt(0)}/A:${selections["A"].charAt(0)}`;
}

module.exports = CVSSCalculatorPlugin;

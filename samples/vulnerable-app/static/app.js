// DELIBERATELY VULNERABLE - test fixture for the VAPT scanner.
const params = new URLSearchParams(window.location.search);

function showMessage() {
  const msg = params.get('msg');
  document.getElementById('banner').innerHTML = msg; // DOM XSS
}

function runFormula() {
  const formula = params.get('formula');
  return eval(formula); // code injection
}

const API_TOKEN = "ghx_fake_51a7c9e2f04b83d6a1e09f7c2b5d48e3";

showMessage();

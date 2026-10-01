const themeToggleBtn = document.getElementById("themeToggleBtn");

// ─── Theme Management ───
function updateThemeIcon(theme) {
  if (themeToggleBtn) {
    // Show Sun to switch to light, Moon to switch to dark.
    themeToggleBtn.textContent = theme === "dark" ? "☀" : "☾";
  }
}

function initTheme() {
  const savedTheme = localStorage.getItem("passlock-theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme");
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("passlock-theme", newTheme);
  updateThemeIcon(newTheme);
}

if (themeToggleBtn) {
  themeToggleBtn.addEventListener("click", toggleTheme);
}
initTheme();

// ─── FAQ Accordion ───
const faqQuestions = document.querySelectorAll('.faq-question');
faqQuestions.forEach(btn => {
  btn.addEventListener('click', () => {
    const faqItem = btn.parentElement;
    const answer = btn.nextElementSibling;
    faqItem.classList.toggle('active');
    if (faqItem.classList.contains('active')) {
      answer.style.maxHeight = answer.scrollHeight + "px";
    } else {
      answer.style.maxHeight = 0;
    }
  });
});
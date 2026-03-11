/* CloudLine Documentation — Interactive JS */

document.addEventListener("DOMContentLoaded", () => {
  // --- Mobile sidebar toggle ---
  const toggle = document.querySelector(".menu-toggle");
  const sidebar = document.querySelector(".sidebar");
  const overlay = document.querySelector(
    ".sidebar-overlay"
  );

  if (toggle) {
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      overlay.classList.toggle("open");
    });
  }

  if (overlay) {
    overlay.addEventListener("click", () => {
      sidebar.classList.remove("open");
      overlay.classList.remove("open");
    });
  }

  // --- Active nav link ---
  const currentPage = window.location.pathname
    .split("/")
    .pop();
  document
    .querySelectorAll(".sidebar nav a")
    .forEach((link) => {
      const href = link.getAttribute("href");
      if (href === currentPage) {
        link.classList.add("active");
      }
    });

  // --- Policy card toggle ---
  document
    .querySelectorAll(".policy-header")
    .forEach((header) => {
      header.addEventListener("click", () => {
        const card = header.closest(".policy-card");
        card.classList.toggle("open");
      });
    });

  // --- Tabs ---
  document.querySelectorAll(".tabs").forEach((tabBar) => {
    const tabs = tabBar.querySelectorAll(".tab");
    const parent = tabBar.parentElement;
    const contents = parent.querySelectorAll(
      ".tab-content"
    );

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        const target = tab.dataset.tab;

        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");

        contents.forEach((c) => {
          c.classList.toggle(
            "active",
            c.dataset.tab === target
          );
        });
      });
    });
  });

  // --- Expand / Collapse all policies ---
  const expandBtn = document.getElementById("expand-all");
  const collapseBtn =
    document.getElementById("collapse-all");

  if (expandBtn) {
    expandBtn.addEventListener("click", () => {
      document
        .querySelectorAll(".policy-card")
        .forEach((c) => c.classList.add("open"));
    });
  }

  if (collapseBtn) {
    collapseBtn.addEventListener("click", () => {
      document
        .querySelectorAll(".policy-card")
        .forEach((c) => c.classList.remove("open"));
    });
  }

  // --- Simple search filter for policies ---
  const searchInput =
    document.getElementById("policy-search");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase();
      document
        .querySelectorAll(".policy-card")
        .forEach((card) => {
          const text = card.textContent.toLowerCase();
          card.style.display = text.includes(query)
            ? ""
            : "none";
        });
    });
  }
});

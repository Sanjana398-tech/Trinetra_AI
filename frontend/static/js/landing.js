(function () {
  "use strict";

  const sections = document.querySelectorAll("main section[id]");
  const links = document.querySelectorAll(".nav-links a");

  if (!sections.length || !links.length || !("IntersectionObserver" in window)) return;

  const observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      links.forEach(function (link) {
        link.classList.toggle("active", link.getAttribute("href") === "#" + entry.target.id);
      });
    });
  }, { rootMargin: "-35% 0px -55%" });

  sections.forEach(function (section) { observer.observe(section); });
})();
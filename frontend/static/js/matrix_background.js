/**
 * TRINETRA AI — Minimalist Cybersecurity Telemetry Stream
 * Clean, sparse, ultra-subtle binary streams with wide column spacing
 * and soft ambient glow that enhances the cybersecurity theme without distraction.
 */
(function () {
  "use strict";

  const canvas = document.getElementById("cyberMatrixCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let width, height;
  let columns = [];
  const colSpacing = 68; // Spaced columns to keep screen clean & uncluttered
  const fontSize = 12;
  const chars = "01010101010101";

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const colCount = Math.floor(width / colSpacing);

    columns = [];
    for (let i = 0; i < colCount; i++) {
      columns.push({
        x: i * colSpacing + (Math.random() * 24 - 12),
        y: Math.random() * -80,
        speed: 0.12 + Math.random() * 0.2,
        opacity: 0.12 + Math.random() * 0.16,
        length: 7 + Math.floor(Math.random() * 8),
      });
    }
  }

  window.addEventListener("resize", resize);
  resize();

  function draw() {
    ctx.clearRect(0, 0, width, height);
    ctx.font = "12px 'JetBrains Mono', monospace";

    for (let i = 0; i < columns.length; i++) {
      const col = columns[i];

      // Draw faint vertical binary stream
      for (let j = 0; j < col.length; j++) {
        const charY = (col.y - j) * (fontSize + 6);
        if (charY < -20 || charY > height + 20) continue;

        const char = chars[Math.floor((col.y + j) * 5) % chars.length];
        const alpha = Math.max(0, col.opacity * (1 - j / col.length));

        if (j === 0) {
          ctx.fillStyle = `rgba(224, 255, 240, ${alpha * 1.4})`;
        } else if (j < 3) {
          ctx.fillStyle = `rgba(0, 229, 255, ${alpha})`;
        } else {
          ctx.fillStyle = `rgba(0, 255, 136, ${alpha * 0.8})`;
        }

        ctx.fillText(char, col.x, charY);
      }

      col.y += col.speed * 0.14;

      if ((col.y - col.length) * (fontSize + 6) > height) {
        col.y = -2;
        col.x = i * colSpacing + (Math.random() * 24 - 12);
        col.opacity = 0.12 + Math.random() * 0.16;
        col.speed = 0.12 + Math.random() * 0.2;
      }
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
})();

"use strict";
// Self-hosted progressive enhancement. The server independently caps the
// selection at 20 and checks refs before any read-only IMAP fetch.
document.addEventListener("DOMContentLoaded", () => {
  const master = document.getElementById("junk-select-all");
  if (!master) return;
  const form = master.closest("form");
  if (!form) return;
  const boxes = [...form.querySelectorAll('input[name="selected"]')];
  const status = document.getElementById("junk-selection-count");
  const cap = 20;
  const update = () => {
    const count = boxes.filter(box => box.checked).length;
    const firstTwenty = boxes.slice(0, cap);
    master.checked = count > 0 && count === firstTwenty.length &&
      firstTwenty.every(box => box.checked) &&
      boxes.slice(cap).every(box => !box.checked);
    master.indeterminate = count > 0 && !master.checked;
    if (status) status.textContent = count + " selected (maximum 20) · 10 MiB total";
  };
  master.addEventListener("change", () => {
    const checked = master.checked;
    boxes.forEach((box, i) => { box.checked = checked && i < cap; });
    update();
  });
  boxes.forEach(box => box.addEventListener("change", () => {
    if (boxes.filter(input => input.checked).length > cap) box.checked = false;
    update();
  }));
  form.addEventListener("submit", () => {
    // Custom manual selections override the special select-all form value.
    if (!boxes.every((box, i) => box.checked === (i < cap))) {
      master.checked = false;
    }
  });
  update();
});

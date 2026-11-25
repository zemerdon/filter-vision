"use strict";
// Progressive enhancement: one select-all per independent strategy.
// Without JavaScript, the server still honours select_all=yes.
// Every submitted token is validated against this browser's live analysis.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-coverage-plan]").forEach(form => {
    // HTML form-associated controls live in the table, outside this form node.
    const elements = [...form.elements];
    const boxes = elements.filter(el => el.name === "selected");
    const master = elements.find(el => el.name === "select_all");
    const status = document.querySelector(
      '[data-coverage-count="' + form.id + '"]');
    if (!master || !boxes.length) return;
    const update = () => {
      const count = boxes.filter(box => box.checked).length;
      master.checked = count === boxes.length;
      master.indeterminate = count > 0 && count < boxes.length;
      if (status) status.textContent =
        count + " selected of " + boxes.length + " new rules";
    };
    master.addEventListener("change", () => {
      boxes.forEach(box => { box.checked = master.checked; });
      update();
    });
    boxes.forEach(box => box.addEventListener("change", update));
    form.addEventListener("submit", () => {
      // Prevent select-all overriding a partial manual selection.
      if (!boxes.every(box => box.checked)) master.checked = false;
    });
    update();
  });
  // All saved rules use a separate selection group and common action toolbar.
  document.querySelectorAll("form[data-rule-list]").forEach(form => {
    const controls = [...form.elements];
    const boxes = controls.filter(el => el.name === "selected");
    const master = controls.find(el => el.name === "select_all");
    const status = document.querySelector('[data-rule-count="' + form.id + '"]');
    if (!master || !boxes.length) return;
    const update = () => {
      const selected = boxes.filter(el => el.checked).length;
      master.checked = selected === boxes.length;
      master.indeterminate = selected > 0 && selected < boxes.length;
      if (status) status.textContent = selected + " of " + boxes.length + " rules selected";
    };
    master.addEventListener("change", () => {
      boxes.forEach(box => { box.checked = master.checked; });
      update();
    });
    boxes.forEach(box => box.addEventListener("change", update));
    form.addEventListener("submit", () => {
      if (!boxes.every(box => box.checked)) master.checked = false;
    });
    update();
  });
});

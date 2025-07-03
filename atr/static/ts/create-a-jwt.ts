document.addEventListener("DOMContentLoaded", (): void => {
  const form = document.getElementById("issue-jwt-form") as HTMLFormElement | null;
  const output = document.getElementById("jwt-output");

  if (!form || !output) {
    return;
  }

  form.addEventListener("submit", async (e: Event): Promise<void> => {
    e.preventDefault();

    const resp = await fetch(form.action, {
      method: "POST",
      body: new FormData(form),
    });

    if (resp.ok) {
      const token = await resp.text();
      output.classList.remove("d-none");
      output.textContent = token;
    } else {
      alert("Failed to fetch JWT");
    }
  });
});

function updateDeleteButton(inputElement, buttonId) {
  let button = document.getElementById(buttonId);
  button.disabled = inputElement.value !== "DELETE";
}

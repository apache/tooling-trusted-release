function init() {
    document.addEventListener("DOMContentLoaded", function () {
        const copyButtons = document.querySelectorAll(".atr-copy-btn");

        copyButtons.forEach(button => {
            button.addEventListener("click", function () {
                const targetId = this.getAttribute("data-clipboard-target");
                const targetElement = document.querySelector(targetId);

                if (targetElement) {
                    const textToCopy = targetElement.textContent;

                    navigator.clipboard.writeText(textToCopy)
                        .then(() => {
                            const originalText = this.innerHTML;
                            this.innerHTML = '<i class="bi bi-check2"></i> Copied!';

                            // Reset the button text after 2000ms
                            setTimeout(() => {
                                this.innerHTML = originalText;
                            }, 2000);
                        })
                        .catch(err => {
                            console.error("Failed to copy: ", err);
                            this.innerHTML = '<i class="bi bi-exclamation-triangle"></i> Failed!';

                            setTimeout(() => {
                                this.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
                            }, 2000);
                        });
                }
            });
        });
    });
}

function updateDeleteButton(inputElement, buttonId) {
    let button = document.getElementById(buttonId);
    button.disabled = inputElement.value !== "DELETE";
}

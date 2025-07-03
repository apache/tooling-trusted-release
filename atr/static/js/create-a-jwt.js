"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("issue-jwt-form");
    const output = document.getElementById("jwt-output");
    if (!form || !output) {
        return;
    }
    form.addEventListener("submit", (e) => __awaiter(void 0, void 0, void 0, function* () {
        e.preventDefault();
        const resp = yield fetch(form.action, {
            method: "POST",
            body: new FormData(form),
        });
        if (resp.ok) {
            const token = yield resp.text();
            output.classList.remove("d-none");
            output.textContent = token;
        }
        else {
            alert("Failed to fetch JWT");
        }
    }));
});
//# sourceMappingURL=create-a-jwt.js.map

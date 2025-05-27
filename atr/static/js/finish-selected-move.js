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
var ItemType;
(function (ItemType) {
    ItemType["File"] = "file";
    ItemType["Dir"] = "dir";
})(ItemType || (ItemType = {}));
const ID = Object.freeze({
    confirmMoveButton: "confirm-move-button",
    currentMoveSelectionInfo: "current-move-selection-info",
    dirData: "dir-data",
    dirFilterInput: "dir-filter-input",
    dirListMoreInfo: "dir-list-more-info",
    dirListTableBody: "dir-list-table-body",
    errorAlert: "move-error-alert",
    fileData: "file-data",
    fileFilter: "file-filter",
    fileListMoreInfo: "file-list-more-info",
    fileListTableBody: "file-list-table-body",
    mainScriptData: "main-script-data",
    maxFilesInput: "max-files-input",
    selectedFileNameTitle: "selected-file-name-title",
});
const TXT = Object.freeze({
    Choose: "Choose",
    Chosen: "Chosen",
    Select: "Select",
    Selected: "Selected",
    MoreItemsHint: "more available (filter to browse)..."
});
const MAX_FILES_FALLBACK = 5;
let fileFilterInput;
let fileListTableBody;
let maxFilesInput;
let selectedFileNameTitleElement;
let dirFilterInput;
let dirListTableBody;
let confirmMoveButton;
let currentMoveSelectionInfoElement;
let errorAlert;
let uiState;
function toLower(s) {
    return (s || "").toLocaleLowerCase();
}
function includesCaseInsensitive(haystack, needle) {
    if (haystack === null || haystack === undefined || needle === null || needle === undefined)
        return false;
    return toLower(haystack).includes(toLower(needle));
}
function getParentPath(filePathString) {
    if (!filePathString || typeof filePathString !== "string")
        return ".";
    const lastSlash = filePathString.lastIndexOf("/");
    if (lastSlash === -1)
        return ".";
    if (lastSlash === 0)
        return "/";
    return filePathString.substring(0, lastSlash);
}
function assertElementPresent(element, selector) {
    if (!element) {
        throw new Error(`Required DOM element '${selector}' not found.`);
    }
    return element;
}
function $(id) {
    return assertElementPresent(document.getElementById(id), id);
}
function updateMoveSelectionInfo() {
    if (selectedFileNameTitleElement) {
        selectedFileNameTitleElement.textContent = uiState.currentlySelectedFilePaths.size > 0
            ? `Select a destination for ${uiState.currentlySelectedFilePaths.size} file(s)`
            : "Select a destination for the file";
    }
    const numSelectedFiles = uiState.currentlySelectedFilePaths.size;
    const destinationDir = uiState.currentlyChosenDirectoryPath;
    let message = "Please select files and a destination.";
    let disableConfirmButton = true;
    currentMoveSelectionInfoElement.innerHTML = '';
    if (!numSelectedFiles && destinationDir) {
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Selected destination: "));
        const strongDest = document.createElement("strong");
        strongDest.textContent = destinationDir;
        currentMoveSelectionInfoElement.appendChild(strongDest);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(". Please select file(s) to move."));
    }
    else if (numSelectedFiles && !destinationDir) {
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Moving "));
        const strongN = document.createElement("strong");
        strongN.textContent = `${numSelectedFiles} file(s)`;
        currentMoveSelectionInfoElement.appendChild(strongN);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(" to (select destination)."));
    }
    else if (numSelectedFiles && destinationDir) {
        const filesArray = Array.from(uiState.currentlySelectedFilePaths);
        const displayFiles = filesArray.length > 1 ? `${filesArray[0]} and ${filesArray.length - 1} other(s)` : filesArray[0];
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Move "));
        const strongDisplayFiles = document.createElement("strong");
        strongDisplayFiles.textContent = displayFiles;
        currentMoveSelectionInfoElement.appendChild(strongDisplayFiles);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(" to "));
        const strongDest = document.createElement("strong");
        strongDest.textContent = destinationDir;
        currentMoveSelectionInfoElement.appendChild(strongDest);
        message = "";
        disableConfirmButton = false;
    }
    if (message && currentMoveSelectionInfoElement.childNodes.length === 0) {
        currentMoveSelectionInfoElement.textContent = message;
    }
    confirmMoveButton.disabled = disableConfirmButton;
}
function renderListItems(tbodyElement, items, config) {
    const fragment = new DocumentFragment();
    const itemsToShow = items.slice(0, uiState.maxFilesToShow);
    itemsToShow.forEach(item => {
        const itemPathString = (config.itemType === ItemType.Dir && !item) ? "." : String(item || "");
        const row = document.createElement("tr");
        row.className = "page-table-row-interactive";
        const controlCell = row.insertCell();
        controlCell.className = "page-table-button-cell text-end";
        const pathCell = row.insertCell();
        pathCell.className = "page-table-path-cell";
        const span = document.createElement("span");
        span.className = "page-file-select-text";
        span.textContent = itemPathString;
        switch (config.itemType) {
            case ItemType.File: {
                const checkbox = document.createElement("input");
                checkbox.type = "checkbox";
                checkbox.className = "form-check-input ms-2";
                checkbox.dataset.filePath = itemPathString;
                checkbox.checked = uiState.currentlySelectedFilePaths.has(itemPathString);
                checkbox.setAttribute("aria-label", `Select file ${itemPathString}`);
                if (uiState.currentlyChosenDirectoryPath && getParentPath(itemPathString) === uiState.currentlyChosenDirectoryPath) {
                    checkbox.disabled = true;
                    span.classList.add("page-extra-muted");
                }
                controlCell.appendChild(checkbox);
                break;
            }
            case ItemType.Dir: {
                const radio = document.createElement("input");
                radio.type = "radio";
                radio.name = "target-directory-radio";
                radio.className = "form-check-input ms-2";
                radio.value = itemPathString;
                radio.dataset.dirPath = itemPathString;
                radio.checked = itemPathString === config.selectedItem;
                radio.setAttribute("aria-label", `Choose directory ${itemPathString}`);
                if (itemPathString === config.selectedItem) {
                    row.classList.add("page-item-selected");
                    row.setAttribute("aria-selected", "true");
                    span.classList.add("fw-bold");
                }
                else {
                    row.setAttribute("aria-selected", "false");
                }
                controlCell.appendChild(radio);
                break;
            }
        }
        pathCell.appendChild(span);
        fragment.appendChild(row);
    });
    tbodyElement.replaceChildren(fragment);
    const moreInfoElement = document.getElementById(config.moreInfoId);
    if (moreInfoElement) {
        if (items.length > uiState.maxFilesToShow) {
            moreInfoElement.textContent = `${items.length - uiState.maxFilesToShow} ${TXT.MoreItemsHint}`;
            moreInfoElement.style.display = "block";
        }
        else {
            moreInfoElement.textContent = "";
            moreInfoElement.style.display = "none";
        }
    }
}
function renderAllLists() {
    const filteredFilePaths = uiState.originalFilePaths.filter(fp => includesCaseInsensitive(fp, uiState.filters.file));
    const filesConfig = {
        itemType: ItemType.File,
        selectedItem: null,
        moreInfoId: ID.fileListMoreInfo
    };
    renderListItems(fileListTableBody, filteredFilePaths, filesConfig);
    const filteredDirs = uiState.allTargetDirs.filter(dirP => includesCaseInsensitive(dirP, uiState.filters.dir));
    const dirsConfig = {
        itemType: ItemType.Dir,
        selectedItem: uiState.currentlyChosenDirectoryPath,
        moreInfoId: ID.dirListMoreInfo
    };
    renderListItems(dirListTableBody, filteredDirs, dirsConfig);
    updateMoveSelectionInfo();
}
function handleDirSelection(dirPath) {
    uiState.currentlyChosenDirectoryPath = dirPath;
    renderAllLists();
}
function delegate(parent, selector, handler) {
    parent.addEventListener("click", (e) => {
        const targetElement = e.target;
        if (targetElement) {
            const el = targetElement.closest(selector);
            if (el instanceof HTMLElement) {
                handler(el, e);
            }
        }
    });
}
function handleFileCheckbox(checkbox) {
    const filePath = checkbox.dataset.filePath;
    if (filePath) {
        if (checkbox.checked) {
            uiState.currentlySelectedFilePaths.add(filePath);
        }
        else {
            uiState.currentlySelectedFilePaths.delete(filePath);
        }
        renderAllLists();
    }
}
function handleDirRadio(radio) {
    if (radio.checked) {
        const dirPath = radio.dataset.dirPath || null;
        handleDirSelection(dirPath);
    }
}
function setState(partial) {
    uiState = Object.assign(Object.assign({}, uiState), partial);
    renderAllLists();
}
function onFileFilterInput(event) {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
        setState({ filters: Object.assign(Object.assign({}, uiState.filters), { file: target.value }) });
    }
}
function onDirFilterInput(event) {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
        setState({ filters: Object.assign(Object.assign({}, uiState.filters), { dir: target.value }) });
    }
}
function onMaxFilesChange(event) {
    const target = event.target;
    const newValue = parseInt(target.value, 10);
    if (newValue >= 1) {
        setState({ maxFilesToShow: newValue });
    }
    else {
        target.value = String(uiState.maxFilesToShow);
    }
}
function isErrorResponse(data) {
    return typeof data === 'object' && data !== null &&
        (('message' in data && typeof data.message === 'string') ||
            ('error' in data && typeof data.error === 'string'));
}
function moveFiles(files, dest, csrfToken, signal) {
    return __awaiter(this, void 0, void 0, function* () {
        const formData = new FormData();
        formData.append("csrf_token", csrfToken);
        for (const file of files) {
            formData.append("source_files", file);
        }
        formData.append("target_directory", dest);
        try {
            const response = yield fetch(window.location.pathname, {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: {
                    "Accept": "application/json",
                },
                signal,
            });
            if (response.ok) {
                return { ok: true };
            }
            else {
                let errorMsg = `An error occurred while moving the file (Status: ${response.status})`;
                if (response.status === 403)
                    errorMsg = "Permission denied to move the file.";
                if (response.status === 400)
                    errorMsg = "Invalid request to move the file.";
                if (signal === null || signal === void 0 ? void 0 : signal.aborted) {
                    errorMsg = "Move operation aborted.";
                }
                try {
                    const errorData = yield response.json();
                    if (isErrorResponse(errorData)) {
                        if (errorData.message) {
                            errorMsg = errorData.message;
                        }
                        else if (errorData.error) {
                            errorMsg = errorData.error;
                        }
                    }
                }
                catch ( /* Do nothing */_a) { /* Do nothing */ }
                return { ok: false, message: errorMsg };
            }
        }
        catch (error) {
            // console.error("Network or fetch error:", error);
            if (error instanceof Error && error.name === 'AbortError') {
                return { ok: false, message: "Move operation aborted." };
            }
            return { ok: false, message: "A network error occurred. Please check your connection and try again." };
        }
    });
}
function splitMoveCandidates(selected, dest) {
    const toMoveMutable = [];
    const alreadyThereMutable = [];
    for (const filePath of selected) {
        if (getParentPath(filePath) === dest) {
            alreadyThereMutable.push(filePath);
        }
        else {
            toMoveMutable.push(filePath);
        }
    }
    return { toMove: toMoveMutable, alreadyThere: alreadyThereMutable };
}
function onConfirmMoveClick() {
    return __awaiter(this, void 0, void 0, function* () {
        errorAlert.classList.add("d-none");
        errorAlert.textContent = "";
        const controller = new AbortController();
        window.addEventListener("beforeunload", () => controller.abort());
        if (uiState.currentlySelectedFilePaths.size > 0 && uiState.currentlyChosenDirectoryPath && uiState.csrfToken) {
            const { toMove, alreadyThere: filesAlreadyInDest } = splitMoveCandidates(uiState.currentlySelectedFilePaths, uiState.currentlyChosenDirectoryPath);
            if (toMove.length === 0 && filesAlreadyInDest.length > 0 && uiState.currentlySelectedFilePaths.size > 0) {
                errorAlert.classList.remove("d-none");
                errorAlert.textContent = `All selected files (${filesAlreadyInDest.join(", ")}) are already in the target directory. No files were moved.`;
                confirmMoveButton.disabled = false;
                return;
            }
            if (filesAlreadyInDest.length > 0) {
                const alreadyInDestMsg = `Note: ${filesAlreadyInDest.join(", ")} ${filesAlreadyInDest.length === 1 ? "is" : "are"} already in the target directory and will not be moved.`;
                const existingError = errorAlert.textContent;
                errorAlert.textContent = existingError ? `${existingError} ${alreadyInDestMsg}` : alreadyInDestMsg;
            }
            const result = yield moveFiles(toMove, uiState.currentlyChosenDirectoryPath, uiState.csrfToken, controller.signal);
            if (result.ok) {
                window.location.reload();
            }
            else {
                errorAlert.classList.remove("d-none");
                errorAlert.textContent = result.message;
            }
        }
        else {
            errorAlert.classList.remove("d-none");
            errorAlert.textContent = "Please select file(s) and a destination directory.";
        }
    });
}
document.addEventListener("DOMContentLoaded", () => {
    var _a, _b, _c, _d;
    fileFilterInput = $(ID.fileFilter);
    fileListTableBody = $(ID.fileListTableBody);
    maxFilesInput = $(ID.maxFilesInput);
    selectedFileNameTitleElement = $(ID.selectedFileNameTitle);
    dirFilterInput = $(ID.dirFilterInput);
    dirListTableBody = $(ID.dirListTableBody);
    confirmMoveButton = $(ID.confirmMoveButton);
    currentMoveSelectionInfoElement = $(ID.currentMoveSelectionInfo);
    currentMoveSelectionInfoElement.setAttribute("aria-live", "polite");
    errorAlert = $(ID.errorAlert);
    let initialFilePaths = [];
    let initialTargetDirs = [];
    try {
        const fileData = (_a = document.getElementById(ID.fileData)) === null || _a === void 0 ? void 0 : _a.textContent;
        if (fileData)
            initialFilePaths = JSON.parse(fileData);
        const dirData = (_b = document.getElementById(ID.dirData)) === null || _b === void 0 ? void 0 : _b.textContent;
        if (dirData)
            initialTargetDirs = JSON.parse(dirData);
    }
    catch (_e) {
        // console.error("Error parsing JSON data:");
    }
    const csrfToken = (_d = (_c = document
        .querySelector(`#${ID.mainScriptData}`)) === null || _c === void 0 ? void 0 : _c.dataset.csrfToken) !== null && _d !== void 0 ? _d : null;
    uiState = {
        filters: {
            file: fileFilterInput.value || "",
            dir: dirFilterInput.value || "",
        },
        maxFilesToShow: Math.max(parseInt(maxFilesInput.value, 10) || 0, 1) || MAX_FILES_FALLBACK,
        currentlySelectedFilePaths: new Set(),
        currentlyChosenDirectoryPath: null,
        originalFilePaths: initialFilePaths,
        allTargetDirs: initialTargetDirs,
        csrfToken,
    };
    maxFilesInput.value = String(uiState.maxFilesToShow);
    fileFilterInput.addEventListener("input", onFileFilterInput);
    dirFilterInput.addEventListener("input", onDirFilterInput);
    maxFilesInput.addEventListener("change", onMaxFilesChange);
    delegate(fileListTableBody, "input[type='checkbox'][data-file-path]", handleFileCheckbox);
    delegate(dirListTableBody, "input[type='radio'][name='target-directory-radio']", handleDirRadio);
    confirmMoveButton.addEventListener("click", () => {
        onConfirmMoveClick().catch(_err => {
            // console.error("Error in onConfirmMoveClick handler:", _err);
            if (errorAlert) {
                errorAlert.classList.remove("d-none");
                errorAlert.textContent = "An unexpected error occurred. Please try again.";
            }
        });
    });
    renderAllLists();
});
//# sourceMappingURL=finish-selected-move.js.map

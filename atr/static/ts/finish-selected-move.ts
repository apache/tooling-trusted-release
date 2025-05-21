"use strict";

enum ItemType {
    File = "file",
    Dir = "dir",
}

const CONFIRM_MOVE_BUTTON_ID = "confirm-move-button";
const CURRENT_MOVE_SELECTION_INFO_ID = "current-move-selection-info";
const DIR_DATA_ID = "dir-data";
const DIR_FILTER_INPUT_ID = "dir-filter-input";
const DIR_LIST_MORE_INFO_ID = "dir-list-more-info";
const DIR_LIST_TABLE_BODY_ID = "dir-list-table-body";
const ERROR_ALERT_ID = "move-error-alert";
const FILE_DATA_ID = "file-data";
const FILE_FILTER_ID = "file-filter";
const FILE_LIST_MORE_INFO_ID = "file-list-more-info";
const FILE_LIST_TABLE_BODY_ID = "file-list-table-body";
const MAIN_SCRIPT_DATA_ID = "main-script-data";
const MAX_FILES_INPUT_ID = "max-files-input";
const SELECTED_FILE_NAME_TITLE_ID = "selected-file-name-title";

const TXT_CHOOSE = "Choose";
const TXT_CHOSEN = "Chosen";
const TXT_SELECT = "Select";
const TXT_SELECTED = "Selected";

const MAX_FILES_FALLBACK = 5;

interface ButtonDataset extends DOMStringMap {
    filePath?: string;
    dirPath?: string;
}

type ButtonClickEvent = MouseEvent & {
    currentTarget: HTMLButtonElement & { dataset: ButtonDataset };
};

type FilterInputEvent = Event & {
    target: HTMLInputElement;
};

interface UIState {
    fileFilter: string;
    dirFilter: string;
    maxFilesToShow: number;
    currentlySelectedFilePath: string | null;
    currentlyChosenDirectoryPath: string | null;
    originalFilePaths: string[];
    allTargetDirs: string[];
    csrfToken: string | null;
}

interface RenderListDisplayConfig {
    itemType: ItemType;
    selectedItem: string | null;
    buttonClassBase: string;
    buttonClassOutline: string;
    buttonClassActive: string;
    buttonTextSelected: string;
    buttonTextDefault: string;
    moreInfoId: string;
}

let fileFilterInput: HTMLInputElement;
let fileListTableBody: HTMLTableSectionElement;
let maxFilesInput: HTMLInputElement;
let selectedFileNameTitleElement: HTMLElement;
let dirFilterInput: HTMLInputElement;
let dirListTableBody: HTMLTableSectionElement;
let confirmMoveButton: HTMLButtonElement;
let currentMoveSelectionInfoElement: HTMLElement;
let errorAlert: HTMLElement;

let uiState: UIState;

function getParentPath(filePathString: string | null | undefined): string {
    if (!filePathString || typeof filePathString !== "string") return ".";
    const lastSlash = filePathString.lastIndexOf("/");
    if (lastSlash === -1) return ".";
    if (lastSlash === 0) return "/";
    return filePathString.substring(0, lastSlash);
}

const toLower = (s: string | null | undefined): string => (s || "").toLocaleLowerCase();

const includesCaseInsensitive = (haystack: string | null | undefined, lowerNeedle: string): boolean =>
    toLower(haystack).includes(lowerNeedle);

function assertElementPresent<T extends HTMLElement>(element: T | null, selector: string): T {
    if (!element) {
        throw new Error(`Required DOM element '${selector}' not found.`);
    }
    return element;
}

function updateMoveSelectionInfo(): void {
    if (selectedFileNameTitleElement) {
        selectedFileNameTitleElement.textContent = uiState.currentlySelectedFilePath
            ? `Select a destination for ${uiState.currentlySelectedFilePath}`
            : "Select a destination for the file";
    }

    let infoHTML = "";
    let disableConfirm = true;

    if (!uiState.currentlySelectedFilePath && uiState.currentlyChosenDirectoryPath) {
        infoHTML = `Selected destination: <strong>${uiState.currentlyChosenDirectoryPath}</strong>. Please select a file to move.`;
    } else if (uiState.currentlySelectedFilePath && !uiState.currentlyChosenDirectoryPath) {
        infoHTML = `Moving <strong>${uiState.currentlySelectedFilePath}</strong> to (select destination).`;
    } else if (uiState.currentlySelectedFilePath && uiState.currentlyChosenDirectoryPath) {
        infoHTML = `Move <strong>${uiState.currentlySelectedFilePath}</strong> to <strong>${uiState.currentlyChosenDirectoryPath}</strong>`;
        disableConfirm = false;
    } else {
        infoHTML = "Please select a file and a destination.";
    }

    currentMoveSelectionInfoElement.innerHTML = infoHTML;
    confirmMoveButton.disabled = disableConfirm;
}

function renderListItems(
    tbodyElement: HTMLTableSectionElement,
    items: string[],
    config: RenderListDisplayConfig
): void {
    const fragment = new DocumentFragment();
    const itemsToShow = items.slice(0, uiState.maxFilesToShow);

    itemsToShow.forEach(item => {
        const itemPathString = config.itemType === ItemType.Dir && !item ? "." : String(item || "");
        const row = document.createElement("tr");
        row.className = "atr-table-row-interactive";

        const buttonCell = row.insertCell();
        buttonCell.className = "page-table-button-cell text-end";
        const pathCell = row.insertCell();
        pathCell.className = "page-table-path-cell";

        const span = document.createElement("span");
        span.className = "page-file-select-text";
        span.textContent = itemPathString;

        if (itemPathString === config.selectedItem) {
            row.classList.add("page-item-selected");
            row.setAttribute("aria-selected", "true");
            span.classList.add("fw-bold");

            const arrowSpan = document.createElement("span");
            arrowSpan.className = "text-success fs-1";
            arrowSpan.textContent = "→";
            buttonCell.appendChild(arrowSpan);
        } else {
            row.setAttribute("aria-selected", "false");

            const button = document.createElement("button") as HTMLButtonElement & { dataset: ButtonDataset };
            button.type = "button";
            button.className = `btn btn-sm ${config.buttonClassBase} ${config.buttonClassOutline}`;
            button.dataset[config.itemType === ItemType.File ? "filePath" : "dirPath"] = itemPathString;
            button.textContent = config.buttonTextDefault;

            buttonCell.appendChild(button);
        }

        pathCell.appendChild(span);
        fragment.appendChild(row);
    });

    tbodyElement.replaceChildren(fragment);

    const moreInfoElement = document.getElementById(config.moreInfoId) as HTMLElement | null;
    if (moreInfoElement) {
        if (items.length > uiState.maxFilesToShow) {
            moreInfoElement.textContent = `${items.length - uiState.maxFilesToShow} more available (filter to browse)...`;
            moreInfoElement.style.display = "block";
        } else {
            moreInfoElement.textContent = "";
            moreInfoElement.style.display = "none";
        }
    }
}

function renderAllLists(): void {
    const lowerFileFilter = toLower(uiState.fileFilter);
    const filteredFilePaths = uiState.originalFilePaths.filter(fp =>
        includesCaseInsensitive(fp, lowerFileFilter)
    );
    const filesConfig: RenderListDisplayConfig = {
        itemType: ItemType.File,
        selectedItem: uiState.currentlySelectedFilePath,
        buttonClassBase: "select-file-btn",
        buttonClassOutline: "btn-outline-primary",
        buttonClassActive: "btn-primary",
        buttonTextSelected: TXT_SELECTED,
        buttonTextDefault: TXT_SELECT,
        moreInfoId: FILE_LIST_MORE_INFO_ID
    };
    renderListItems(fileListTableBody, filteredFilePaths, filesConfig);

    const lowerDirFilter = toLower(uiState.dirFilter);
    const filteredDirs = uiState.allTargetDirs.filter(dirP =>
        includesCaseInsensitive(dirP, lowerDirFilter)
    );
    const dirsConfig: RenderListDisplayConfig = {
        itemType: ItemType.Dir,
        selectedItem: uiState.currentlyChosenDirectoryPath,
        buttonClassBase: "choose-dir-btn",
        buttonClassOutline: "btn-outline-secondary",
        buttonClassActive: "btn-secondary",
        buttonTextSelected: TXT_CHOSEN,
        buttonTextDefault: TXT_CHOOSE,
        moreInfoId: DIR_LIST_MORE_INFO_ID
    };
    renderListItems(dirListTableBody, filteredDirs, dirsConfig);

    updateMoveSelectionInfo();
}

function handleFileSelection(filePath: string | null): void {
    if (uiState.currentlyChosenDirectoryPath) {
        const parentOfNewFile = getParentPath(filePath);
        if (parentOfNewFile === uiState.currentlyChosenDirectoryPath) {
            uiState.currentlyChosenDirectoryPath = null;
        }
    }
    uiState.currentlySelectedFilePath = filePath;
    renderAllLists();
}

function handleDirSelection(dirPath: string | null): void {
    if (dirPath && uiState.currentlySelectedFilePath && getParentPath(uiState.currentlySelectedFilePath) === dirPath) uiState.currentlySelectedFilePath = null;
    uiState.currentlyChosenDirectoryPath = dirPath;
    renderAllLists();
}

function onFileListClick(event: Event): void {
    const targetElement = event.target as HTMLElement;
    const button = targetElement.closest<HTMLButtonElement>("button.select-file-btn");
    if (button && !button.disabled) {
        const filePath = button.dataset.filePath || null;
        handleFileSelection(filePath);
    }
}

function onDirListClick(event: Event): void {
    const targetElement = event.target as HTMLElement;
    const button = targetElement.closest<HTMLButtonElement>("button.choose-dir-btn");
    if (button && !button.disabled) {
        const dirPath = button.dataset.dirPath || null;
        handleDirSelection(dirPath);
    }
}

function onFileFilterInput(event: FilterInputEvent): void {
    uiState.fileFilter = event.target.value;
    renderAllLists();
}

function onDirFilterInput(event: FilterInputEvent): void {
    uiState.dirFilter = event.target.value;
    renderAllLists();
}

function onMaxFilesChange(event: FilterInputEvent): void {
    const newValue = parseInt(event.target.value, 10);
    if (newValue >= 1) {
        uiState.maxFilesToShow = newValue;
        renderAllLists();
    } else {
        event.target.value = String(uiState.maxFilesToShow);
    }
}

async function onConfirmMoveClick(): Promise<void> {
    errorAlert.classList.add("d-none");
    if (uiState.currentlySelectedFilePath && uiState.currentlyChosenDirectoryPath && uiState.csrfToken) {
        const formData = new FormData();
        formData.append("csrf_token", uiState.csrfToken);
        formData.append("source_file", uiState.currentlySelectedFilePath);
        formData.append("target_directory", uiState.currentlyChosenDirectoryPath);

        try {
            const response = await fetch(window.location.pathname, {
                method: "POST",
                body: formData,
                credentials: "same-origin",
                headers: {
                    "Accept": "application/json",
                },
            });

            if (response.ok) {
                window.location.reload();
            } else {
                let errorMsg = `An error occurred while moving the file (Status: ${response.status})`;
                if (response.status === 403) errorMsg = "Permission denied to move the file.";
                if (response.status === 400) errorMsg = "Invalid request to move the file.";
                try {
                    const errorData = await response.json();
                    if (errorData && typeof errorData.error === "string") errorMsg = errorData.error;
                } catch (_) { }
                errorAlert.textContent = errorMsg;
                errorAlert.classList.remove("d-none");
                return;
            }
        } catch (error) {
            console.error("Network or fetch error:", error);
            errorAlert.textContent = "A network error occurred. Please check your connection and try again.";
            errorAlert.classList.remove("d-none");
        }
    } else {
        errorAlert.textContent = "Please select both a file to move and a destination directory.";
        errorAlert.classList.remove("d-none");
    }
}

document.addEventListener("DOMContentLoaded", function () {
    fileFilterInput = assertElementPresent(document.querySelector<HTMLInputElement>(`#${FILE_FILTER_ID}`), FILE_FILTER_ID);
    fileListTableBody = assertElementPresent(document.querySelector<HTMLTableSectionElement>(`#${FILE_LIST_TABLE_BODY_ID}`), FILE_LIST_TABLE_BODY_ID);
    maxFilesInput = assertElementPresent(document.querySelector<HTMLInputElement>(`#${MAX_FILES_INPUT_ID}`), MAX_FILES_INPUT_ID);
    selectedFileNameTitleElement = assertElementPresent(document.getElementById(SELECTED_FILE_NAME_TITLE_ID) as HTMLElement, SELECTED_FILE_NAME_TITLE_ID);
    dirFilterInput = assertElementPresent(document.querySelector<HTMLInputElement>(`#${DIR_FILTER_INPUT_ID}`), DIR_FILTER_INPUT_ID);
    dirListTableBody = assertElementPresent(document.querySelector<HTMLTableSectionElement>(`#${DIR_LIST_TABLE_BODY_ID}`), DIR_LIST_TABLE_BODY_ID);
    confirmMoveButton = assertElementPresent(document.querySelector<HTMLButtonElement>(`#${CONFIRM_MOVE_BUTTON_ID}`), CONFIRM_MOVE_BUTTON_ID);
    currentMoveSelectionInfoElement = assertElementPresent(document.getElementById(CURRENT_MOVE_SELECTION_INFO_ID) as HTMLElement, CURRENT_MOVE_SELECTION_INFO_ID);
    currentMoveSelectionInfoElement.setAttribute("aria-live", "polite");
    errorAlert = assertElementPresent(document.getElementById(ERROR_ALERT_ID) as HTMLElement, ERROR_ALERT_ID);

    let initialFilePaths: string[] = [];
    let initialTargetDirs: string[] = [];
    try {
        const fileDataElement = document.getElementById(FILE_DATA_ID);
        if (fileDataElement?.textContent) {
            initialFilePaths = JSON.parse(fileDataElement.textContent);
        }
        const dirDataElement = document.getElementById(DIR_DATA_ID);
        if (dirDataElement?.textContent) {
            initialTargetDirs = JSON.parse(dirDataElement.textContent);
        }
    } catch (e) {
        console.error("Error parsing JSON data:", e);
    }

    if (initialFilePaths.length === 0 && initialTargetDirs.length === 0) {
        alert("Warning: File and/or directory lists could not be loaded or are empty.");
    }

    const mainScriptDataElement = document.querySelector<HTMLElement & { dataset: { csrfToken?: string } }>(`#${MAIN_SCRIPT_DATA_ID}`);
    const initialCsrfToken = mainScriptDataElement?.dataset.csrfToken || null;

    uiState = {
        fileFilter: fileFilterInput.value || "",
        dirFilter: dirFilterInput.value || "",
        maxFilesToShow: parseInt(maxFilesInput.value, 10) || MAX_FILES_FALLBACK,
        currentlySelectedFilePath: null,
        currentlyChosenDirectoryPath: null,
        originalFilePaths: initialFilePaths,
        allTargetDirs: initialTargetDirs,
        csrfToken: initialCsrfToken,
    };
    if (isNaN(uiState.maxFilesToShow) || uiState.maxFilesToShow < 1) {
        uiState.maxFilesToShow = MAX_FILES_FALLBACK;
        maxFilesInput.value = String(uiState.maxFilesToShow);
    }

    fileFilterInput.addEventListener("input", onFileFilterInput as EventListener);
    dirFilterInput.addEventListener("input", onDirFilterInput as EventListener);
    maxFilesInput.addEventListener("change", onMaxFilesChange as EventListener);

    fileListTableBody.addEventListener("click", onFileListClick);
    dirListTableBody.addEventListener("click", onDirListClick);

    confirmMoveButton.addEventListener("click", onConfirmMoveClick);

    renderAllLists();
});

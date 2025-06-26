"use strict";

enum ItemType {
    File = "file",
    Dir = "dir",
}

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
    selectFilesToggleButton: "select-files-toggle-button",
    mainScriptData: "main-script-data",
    maxFilesInput: "max-files-input",
    selectedFileNameTitle: "selected-file-name-title",
} as const);

const TXT = Object.freeze({
    Choose: "Choose",
    Chosen: "Chosen",
    Select: "Select",
    Selected: "Selected",
    MoreItemsHint: "more available (filter to browse)..."
} as const);

const MAX_FILES_FALLBACK = 10;

interface UIState {
    filters: {
        file: string;
        dir: string;
    };
    maxFilesToShow: number;
    currentlySelectedPaths: Set<string>;
    currentlyChosenDirectoryPath: string | null;
    readonly originalSourcePaths: readonly string[];
    readonly allTargetDirs: readonly string[];
    csrfToken: string | null;
}

type RenderListDisplayConfig =
    | { itemType: ItemType.File; selectedItem: null; moreInfoId: string }
    | { itemType: ItemType.Dir; selectedItem: string | null; moreInfoId: string };

let fileFilterInput!: HTMLInputElement;
let fileListTableBody!: HTMLTableSectionElement;
let maxFilesInput!: HTMLInputElement;
let selectedFileNameTitleElement!: HTMLElement;
let dirFilterInput!: HTMLInputElement;
let dirListTableBody!: HTMLTableSectionElement;
let confirmMoveButton!: HTMLButtonElement;
let selectFilesToggleButton!: HTMLButtonElement;
let currentMoveSelectionInfoElement!: HTMLElement;
let errorAlert!: HTMLElement;

let uiState: UIState;

function toLower(s: string | null | undefined): string {
    return (s || "").toLocaleLowerCase();
}

function includesCaseInsensitive(haystack: string | null | undefined, needle: string | null | undefined): boolean {
    if (haystack === null || haystack === undefined || needle === null || needle === undefined) return false;
    return toLower(haystack).includes(toLower(needle));
}

function isValidNewDirName(d: string): boolean {
  return d.length > 0 && !d.includes("..") && !d.startsWith("/") && !d.endsWith("/");
}

function getParentPath(filePathString: string | null | undefined): string {
    if (!filePathString || typeof filePathString !== "string") return ".";
    const lastSlash = filePathString.lastIndexOf("/");
    if (lastSlash === -1) return ".";
    if (lastSlash === 0) return "/";
    return filePathString.substring(0, lastSlash);
}

function assertElementPresent<T extends HTMLElement>(element: T | null, selector: string): T {
    if (!element) {
        throw new Error(`Required DOM element '${selector}' not found.`);
    }
    return element;
}

function $<T extends HTMLElement = HTMLElement>(id: string): T {
  return assertElementPresent(document.getElementById(id) as T | null, id);
}

function updateMoveSelectionInfo(): void {
    if (selectedFileNameTitleElement) {
        selectedFileNameTitleElement.textContent = uiState.currentlySelectedPaths.size > 0
            ? `Select a destination for ${uiState.currentlySelectedPaths.size} item(s)`
            : "Select a destination for the item";
    }

    const numSelectedItems = uiState.currentlySelectedPaths.size;
    const destinationDir = uiState.currentlyChosenDirectoryPath;
    let message = "Please select items and a destination.";
    let disableConfirmButton = true;

    currentMoveSelectionInfoElement.innerHTML = '';

    if (!numSelectedItems && destinationDir) {
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Selected destination: "));
        const strongDest = document.createElement("strong");
        strongDest.textContent = (destinationDir && destinationDir !== "." && !destinationDir.endsWith("/")) ? destinationDir + "/" : destinationDir;
        currentMoveSelectionInfoElement.appendChild(strongDest);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(". Please select item(s) to move."));
    } else if (numSelectedItems && !destinationDir) {
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Moving "));
        const strongN = document.createElement("strong");
        strongN.textContent = `${numSelectedItems} item(s)`;
        currentMoveSelectionInfoElement.appendChild(strongN);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(" to (select destination)."));
    } else if (numSelectedItems && destinationDir) {
        const itemsArray = Array.from(uiState.currentlySelectedPaths);
        const displayItems = itemsArray.length > 1 ? `${itemsArray[0]} and ${itemsArray.length -1} other(s)` : itemsArray[0];
        currentMoveSelectionInfoElement.appendChild(document.createTextNode("Move "));
        const strongDisplayItems = document.createElement("strong");
        strongDisplayItems.textContent = displayItems;
        currentMoveSelectionInfoElement.appendChild(strongDisplayItems);
        currentMoveSelectionInfoElement.appendChild(document.createTextNode(" to "));
        const strongDest = document.createElement("strong");
        strongDest.textContent = (destinationDir && destinationDir !== "." && !destinationDir.endsWith("/")) ? destinationDir + "/" : destinationDir;
        currentMoveSelectionInfoElement.appendChild(strongDest);
        if (destinationDir && uiState.allTargetDirs.indexOf(destinationDir) === -1 && isValidNewDirName(destinationDir)) {
            const newDirSpan = document.createElement("span");
            newDirSpan.textContent = " (will be created)";
            newDirSpan.className = "text-muted small";
            currentMoveSelectionInfoElement.appendChild(newDirSpan);
        }
        message = "";
        disableConfirmButton = false;
    }

    if (message && currentMoveSelectionInfoElement.childNodes.length === 0) {
        currentMoveSelectionInfoElement.textContent = message;
    }

    confirmMoveButton.disabled = disableConfirmButton;
}

function renderListItems(
    tbodyElement: HTMLTableSectionElement,
    items: string[],
    config: RenderListDisplayConfig
): void {
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
                checkbox.dataset.itemPath = itemPathString;
                checkbox.checked = uiState.currentlySelectedPaths.has(itemPathString);
                checkbox.setAttribute("aria-label", `Select item ${itemPathString}`);

                const isKnownSourceDir = uiState.allTargetDirs.indexOf(itemPathString) !== -1;

                if (isKnownSourceDir && itemPathString !== "." && !itemPathString.endsWith("/")) {
                    span.textContent = itemPathString + "/";
                }

                if (uiState.currentlyChosenDirectoryPath && getParentPath(itemPathString) === uiState.currentlyChosenDirectoryPath) {
                    checkbox.disabled = true;
                    span.classList.add("page-extra-muted");
                }
                if (isKnownSourceDir && uiState.currentlyChosenDirectoryPath &&
                    (uiState.currentlyChosenDirectoryPath === itemPathString || uiState.currentlyChosenDirectoryPath.startsWith(itemPathString + "/"))) {
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

                let displayDirPath = itemPathString;
                if (itemPathString !== "." && !itemPathString.endsWith("/")) {
                    displayDirPath = itemPathString + "/";
                }
                span.textContent = displayDirPath;

                if (itemPathString === config.selectedItem) {
                    row.classList.add("page-item-selected");
                    row.setAttribute("aria-selected", "true");
                    span.classList.add("fw-bold");
                } else {
                    row.setAttribute("aria-selected", "false");
                }
                if (itemPathString === uiState.filters.dir.trim() && uiState.allTargetDirs.indexOf(itemPathString) === -1 && isValidNewDirName(itemPathString)){
                    const newDirSpan = document.createElement("span");
                    newDirSpan.textContent = " (new directory)";
                    newDirSpan.className = "text-muted small";
                    span.appendChild(newDirSpan);
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
        } else {
            moreInfoElement.textContent = "";
            moreInfoElement.style.display = "none";
        }
    }
}

function renderAllLists(): void {
    const filteredSourcePaths = uiState.originalSourcePaths.filter(fp =>
        includesCaseInsensitive(fp, uiState.filters.file)
    );
    const itemsConfig: RenderListDisplayConfig = {
        itemType: ItemType.File,
        selectedItem: null,
        moreInfoId: ID.fileListMoreInfo
    };
    renderListItems(fileListTableBody, filteredSourcePaths, itemsConfig);

    const displayDirs = [...uiState.allTargetDirs];
    const trimmedDirFilter = uiState.filters.dir.trim();
    if (isValidNewDirName(trimmedDirFilter) && uiState.allTargetDirs.indexOf(trimmedDirFilter) === -1) {
        displayDirs.push(trimmedDirFilter);
        displayDirs.sort();
    }

    const filteredDirs = displayDirs.filter(dirP =>
        includesCaseInsensitive(dirP, uiState.filters.dir)
    );
    const dirsConfig: RenderListDisplayConfig = {
        itemType: ItemType.Dir,
        selectedItem: uiState.currentlyChosenDirectoryPath,
        moreInfoId: ID.dirListMoreInfo
    };
    renderListItems(dirListTableBody, filteredDirs, dirsConfig);

    updateMoveSelectionInfo();

    if (selectFilesToggleButton) {
        const anySelected = uiState.currentlySelectedPaths.size > 0 || uiState.currentlyChosenDirectoryPath !== null;
        selectFilesToggleButton.textContent = anySelected ? "Unselect all" : "Select these files";
    }
}

function handleDirSelection(dirPath: string | null): void {
    uiState.currentlyChosenDirectoryPath = dirPath;
    renderAllLists();
}

function delegate<T extends HTMLElement>(
  parent: HTMLElement,
  selector: string,
  handler: (el: T, event: Event) => void,
): void {
  parent.addEventListener("click", (e: Event) => {
    const targetElement = e.target as Element | null;
    if (targetElement) {
        const el = targetElement.closest(selector);
        if (el instanceof HTMLElement) {
            handler(el as T, e);
        }
    }
  });
}

function handleItemCheckbox(checkbox: HTMLInputElement): void {
    const itemPath = checkbox.dataset.itemPath;
    if (itemPath) {
        if (checkbox.checked) {
            uiState.currentlySelectedPaths.add(itemPath);
        } else {
            uiState.currentlySelectedPaths.delete(itemPath);
        }
        renderAllLists();
    }
}

function handleDirRadio(radio: HTMLInputElement): void {
    if (radio.checked) {
        const dirPath = radio.dataset.dirPath || null;
        handleDirSelection(dirPath);
    }
}

function setState(partial: Partial<UIState>): void {
  uiState = {...uiState, ...partial};
  renderAllLists();
}

function onFileFilterInput(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
        setState({filters: { ...uiState.filters, file: target.value }});
    }
}

function onDirFilterInput(event: Event): void {
    const target = event.target;
    if (target instanceof HTMLInputElement) {
        setState({filters: { ...uiState.filters, dir: target.value }});
    }
}

function onMaxFilesChange(event: Event): void {
    const target = event.target as HTMLInputElement;
    const newValue = parseInt(target.value, 10);
    if (newValue >= 1) {
        setState({maxFilesToShow: newValue});
    } else {
        target.value = String(uiState.maxFilesToShow);
    }
}

type Ok = { ok: true };
type Err = { ok: false; message: string };

type MoveResult = Ok | Err;

interface ErrorResponse {
    message?: string;
    error?: string;
}

function isErrorResponse(data: unknown): data is ErrorResponse {
    return typeof data === 'object' && data !== null &&
           (('message' in data && typeof (data as {message: unknown}).message === 'string') ||
            ('error' in data && typeof (data as {error: unknown}).error === 'string'));
}

async function moveFiles(files: readonly string[], dest: string, csrfToken: string, signal?: AbortSignal): Promise<MoveResult> {
    const formData = new FormData();
    formData.append("csrf_token", csrfToken);
    for (const file of files) {
        formData.append("source_files", file);
    }
    formData.append("target_directory", dest);

    try {
        const response = await fetch(window.location.pathname, {
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
        } else {
            let errorMsg = `An error occurred while moving the file (Status: ${response.status})`;
            if (response.status === 403) errorMsg = "Permission denied to move the file.";
            if (response.status === 400) errorMsg = "Invalid request to move the file.";
            if (signal?.aborted) {
                errorMsg = "Move operation aborted.";
            }
            try {
                const errorData: unknown = await response.json();
                if (isErrorResponse(errorData)) {
                    if (errorData.message) {
                        errorMsg = errorData.message;
                    } else if (errorData.error) {
                        errorMsg = errorData.error;
                    }
                }
            } catch { /* Do nothing */ }
            return { ok: false, message: errorMsg };
        }
    } catch (error: unknown) {
        // console.error("Network or fetch error:", error);
        if (error instanceof Error && error.name === 'AbortError') {
            return { ok: false, message: "Move operation aborted." };
        }
        return { ok: false, message: "A network error occurred. Please check your connection and try again." };
    }
}

function splitMoveCandidates(
  selected: Iterable<string>,
  dest: string,
): { readonly toMove: readonly string[]; readonly alreadyThere: readonly string[] } {
    const toMoveMutable: string[] = [];
    const alreadyThereMutable: string[] = [];
    for (const filePath of selected) {
        if (getParentPath(filePath) === dest) {
            alreadyThereMutable.push(filePath);
        } else {
            toMoveMutable.push(filePath);
        }
    }
    return { toMove: toMoveMutable, alreadyThere: alreadyThereMutable };
}

async function onConfirmMoveClick(): Promise<void> {
    errorAlert.classList.add("d-none");
    errorAlert.textContent = "";

    const controller = new AbortController();
    window.addEventListener("beforeunload", () => controller.abort());

    if (uiState.currentlySelectedPaths.size > 0 && uiState.currentlyChosenDirectoryPath && uiState.csrfToken) {
        const { toMove, alreadyThere: itemsAlreadyInDest } = splitMoveCandidates(
            uiState.currentlySelectedPaths,
            uiState.currentlyChosenDirectoryPath
        );

        if (toMove.length === 0 && itemsAlreadyInDest.length > 0 && uiState.currentlySelectedPaths.size > 0) {
            errorAlert.classList.remove("d-none");
            errorAlert.textContent = `All selected items (${itemsAlreadyInDest.join(", ")}) are already in the target directory. No items were moved.`;
            confirmMoveButton.disabled = false;
            return;
        }

        if (itemsAlreadyInDest.length > 0) {
            const alreadyInDestMsg = `Note: ${itemsAlreadyInDest.join(", ")} ${itemsAlreadyInDest.length === 1 ? "is" : "are"} already in the target directory and will not be moved.`;
            const existingError = errorAlert.textContent;
            errorAlert.textContent = existingError ? `${existingError} ${alreadyInDestMsg}` : alreadyInDestMsg;
        }

        const result = await moveFiles(toMove, uiState.currentlyChosenDirectoryPath, uiState.csrfToken, controller.signal);

        if (result.ok) {
            window.location.reload();
        } else {
            errorAlert.classList.remove("d-none");
            errorAlert.textContent = result.message;
        }
    } else {
        errorAlert.classList.remove("d-none");
        errorAlert.textContent = "Please select item(s) and a destination directory.";
    }
}

document.addEventListener("DOMContentLoaded", () => {
  fileFilterInput = $<HTMLInputElement>(ID.fileFilter);
  fileListTableBody = $<HTMLTableSectionElement>(ID.fileListTableBody);
  maxFilesInput = $<HTMLInputElement>(ID.maxFilesInput);
  selectedFileNameTitleElement = $(ID.selectedFileNameTitle);
  dirFilterInput = $<HTMLInputElement>(ID.dirFilterInput);
  dirListTableBody = $<HTMLTableSectionElement>(ID.dirListTableBody);
  confirmMoveButton = $<HTMLButtonElement>(ID.confirmMoveButton);
  selectFilesToggleButton = $<HTMLButtonElement>(ID.selectFilesToggleButton);
  currentMoveSelectionInfoElement = $(ID.currentMoveSelectionInfo);
  currentMoveSelectionInfoElement.setAttribute("aria-live", "polite");
  errorAlert = $(ID.errorAlert);

  let initialFilePaths: string[] = [];
  let initialTargetDirs: string[] = [];
  try {
    const fileData = document.getElementById(ID.fileData)?.textContent;
    if (fileData) initialFilePaths = JSON.parse(fileData) as string[];
    const dirData  = document.getElementById(ID.dirData)?.textContent;
    if (dirData)  initialTargetDirs = JSON.parse(dirData) as string[];
  } catch {
    // console.error("Error parsing JSON data:");
  }

  const csrfToken =
    document
      .querySelector<HTMLElement & { dataset: { csrfToken?: string } }>(
        `#${ID.mainScriptData}`,
      )?.dataset.csrfToken ?? null;

  uiState = {
    filters: {
      file: fileFilterInput.value || "",
      dir:  dirFilterInput.value  || "",
    },
    maxFilesToShow:
      Math.max(parseInt(maxFilesInput.value, 10) || 0, 1) || MAX_FILES_FALLBACK,
    currentlySelectedPaths: new Set(),
    currentlyChosenDirectoryPath: null,
    originalSourcePaths: initialFilePaths,
    allTargetDirs: initialTargetDirs,
    csrfToken,
  };
  maxFilesInput.value = String(uiState.maxFilesToShow);

  fileFilterInput.addEventListener("input", onFileFilterInput as EventListener);
  dirFilterInput.addEventListener("input", onDirFilterInput as EventListener);
  maxFilesInput.addEventListener("change", onMaxFilesChange as EventListener);

  delegate<HTMLInputElement>(
    fileListTableBody,
    "input[type='checkbox'][data-item-path]",
    handleItemCheckbox,
  );
  delegate<HTMLInputElement>(
    dirListTableBody,
    "input[type='radio'][name='target-directory-radio']",
    handleDirRadio,
  );
  confirmMoveButton.addEventListener("click", () => {
    onConfirmMoveClick().catch(_err => {
        // console.error("Error in onConfirmMoveClick handler:", _err);
        if (errorAlert) {
            errorAlert.classList.remove("d-none");
            errorAlert.textContent = "An unexpected error occurred. Please try again.";
        }
    });
  });

  selectFilesToggleButton.addEventListener("click", () => {
    const anySelected = uiState.currentlySelectedPaths.size > 0 || uiState.currentlyChosenDirectoryPath !== null;
    if (anySelected) {
        setState({ currentlySelectedPaths: new Set(), currentlyChosenDirectoryPath: null });
    } else {
        const displayedCheckboxes = fileListTableBody.querySelectorAll<HTMLInputElement>("input[type='checkbox'][data-item-path]");
        const newSelected = new Set(uiState.currentlySelectedPaths);
        displayedCheckboxes.forEach(cb => {
            const p = cb.dataset.itemPath;
            if (p) {
                newSelected.add(p);
            }
        });
        setState({ currentlySelectedPaths: newSelected });
    }
  });

  renderAllLists();
});

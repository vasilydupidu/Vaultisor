import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

const loadFromFile = vi.fn();
const restore = vi.fn();
vi.mock("@/lib/api", () => ({
  apiRecoveryLoadFromUsb: (...a: unknown[]) => loadFromFile(...a),
  apiRecoveryRestore: (...a: unknown[]) => restore(...a),
}));

const toastError = vi.fn();
const toastSuccess = vi.fn();
vi.mock("@/components/ui/Toast", () => ({
  useToast: () => ({ error: toastError, success: toastSuccess }),
}));

import { RecoveryFlow } from "./RecoveryFlow";

const PICK = "recoveryFlow.selectFile";
const PASTE_B = "recoveryFlow.partBTitle: recoveryFlow.pasteLabel";
const PASTE_C = "recoveryFlow.partCTitle: recoveryFlow.pasteLabel";

function setup(tpmAvailable: boolean) {
  const onDone = vi.fn();
  const onResetParent = vi.fn();
  render(
    <RecoveryFlow
      reason="forgot-pin"
      tpmAvailable={tpmAvailable}
      onDone={onDone}
      onResetParent={onResetParent}
    />,
  );
  return { onDone, onResetParent };
}

const restoreButton = () => screen.getByRole("button", { name: "recoveryFlow.restore" });
const secretInput = (labelKey: string) => screen.getByLabelText(labelKey) as HTMLInputElement;

const PASSPHRASE = "мой пароль: #1 для сейфа!";

describe("RecoveryFlow", () => {
  beforeEach(() => {
    loadFromFile.mockReset();
    restore.mockReset();
    toastError.mockReset();
    toastSuccess.mockReset();
  });
  afterEach(cleanup);

  it("кнопка восстановления доступна только когда загружены обе части", () => {
    setup(true);
    expect(restoreButton().hasAttribute("disabled")).toBe(true);

    fireEvent.change(screen.getByLabelText(PASTE_B), { target: { value: "1|aa" } });
    expect(restoreButton().hasAttribute("disabled")).toBe(true);

    fireEvent.change(screen.getByLabelText(PASTE_C), { target: { value: "2|bb" } });
    expect(restoreButton().hasAttribute("disabled")).toBe(false);
  });

  it("обе части читаются из файлов и передаются в восстановление по порядку B, C", async () => {
    loadFromFile
      .mockResolvedValueOnce({ share_hex: "1|part-b-from-file" })
      .mockResolvedValueOnce({ share_hex: "2|part-c-from-file" });
    restore.mockResolvedValue({ recovered: true });
    const { onDone, onResetParent } = setup(true);

    const pickButtons = screen.getAllByRole("button", { name: PICK });
    expect(pickButtons).toHaveLength(2);
    await act(async () => {
      fireEvent.click(pickButtons[0]!);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: PICK }));
    });
    // Обе части загружены: на месте слотов — отметки и кнопки «выбрать другую».
    expect(screen.getAllByText("recoveryFlow.partLoaded")).toHaveLength(2);
    expect(loadFromFile).toHaveBeenCalledTimes(2);

    fireEvent.change(secretInput("recoveryFlow.newPin"), { target: { value: "19472856302" } });
    fireEvent.change(secretInput("recoveryFlow.confirmPin"), { target: { value: "19472856302" } });
    await act(async () => {
      fireEvent.click(restoreButton());
    });

    expect(restore).toHaveBeenCalledWith(
      ["1|part-b-from-file", "2|part-c-from-file"],
      "19472856302",
    );
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(onResetParent).toHaveBeenCalledTimes(1);
  });

  it("часть из файла можно сбросить и заменить текстом", async () => {
    loadFromFile.mockResolvedValueOnce({ share_hex: "1|from-file" });
    setup(true);
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: PICK })[0]!);
    });
    expect(screen.queryByLabelText(PASTE_B)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "recoveryFlow.clearPart" }));
    expect(screen.getByLabelText(PASTE_B)).toBeTruthy();
    expect(screen.queryByText("recoveryFlow.partLoaded")).toBeNull();
  });

  it("ошибка чтения файла не заполняет слот", async () => {
    loadFromFile.mockRejectedValueOnce("отмена");
    setup(true);
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: PICK })[0]!);
    });
    expect(toastError).toHaveBeenCalledWith("recoveryFlow.fileReadError");
    expect(screen.queryByText("recoveryFlow.partLoaded")).toBeNull();
  });

  it("одинаковые части не отправляются", async () => {
    setup(true);
    fireEvent.change(screen.getByLabelText(PASTE_B), { target: { value: "1|same" } });
    fireEvent.change(screen.getByLabelText(PASTE_C), { target: { value: " 1|same " } });
    fireEvent.change(secretInput("recoveryFlow.newPin"), { target: { value: "19472856302" } });
    fireEvent.change(secretInput("recoveryFlow.confirmPin"), { target: { value: "19472856302" } });
    await act(async () => {
      fireEvent.click(restoreButton());
    });
    expect(toastError).toHaveBeenCalledWith("recoveryFlow.sharesSame");
    expect(restore).not.toHaveBeenCalled();
  });

  it("без TPM мастер-пароль сохраняет пробелы и символы и уходит как есть", async () => {
    restore.mockResolvedValue({ recovered: true });
    setup(false);
    fireEvent.change(screen.getByLabelText(PASTE_B), { target: { value: "1|aa" } });
    fireEvent.change(screen.getByLabelText(PASTE_C), { target: { value: "2|bb" } });
    fireEvent.change(secretInput("recoveryFlow.newPass"), { target: { value: PASSPHRASE } });
    fireEvent.change(secretInput("recoveryFlow.confirmPass"), { target: { value: PASSPHRASE } });
    expect(secretInput("recoveryFlow.newPass").value).toBe(PASSPHRASE);
    expect(secretInput("recoveryFlow.confirmPass").value).toBe(PASSPHRASE);

    await act(async () => {
      fireEvent.click(restoreButton());
    });
    expect(restore).toHaveBeenCalledWith(["1|aa", "2|bb"], PASSPHRASE);
  });

  it("без TPM слабый пароль (один символ) отклоняется до запроса", async () => {
    setup(false);
    fireEvent.change(screen.getByLabelText(PASTE_B), { target: { value: "1|aa" } });
    fireEvent.change(screen.getByLabelText(PASTE_C), { target: { value: "2|bb" } });
    const weak = "a".repeat(20);
    fireEvent.change(secretInput("recoveryFlow.newPass"), { target: { value: weak } });
    fireEvent.change(secretInput("recoveryFlow.confirmPass"), { target: { value: weak } });
    await act(async () => {
      fireEvent.click(restoreButton());
    });
    expect(toastError).toHaveBeenCalledTimes(1);
    expect(restore).not.toHaveBeenCalled();
  });

  it("с TPM цифровой PIN отфильтровывает всё, кроме цифр", () => {
    setup(true);
    fireEvent.change(secretInput("recoveryFlow.newPin"), { target: { value: "12ab 34-56" } });
    expect(secretInput("recoveryFlow.newPin").value).toBe("123456");
  });

  it("с TPM слишком короткий PIN не отправляется", async () => {
    setup(true);
    fireEvent.change(screen.getByLabelText(PASTE_B), { target: { value: "1|aa" } });
    fireEvent.change(screen.getByLabelText(PASTE_C), { target: { value: "2|bb" } });
    fireEvent.change(secretInput("recoveryFlow.newPin"), { target: { value: "19472" } });
    fireEvent.change(secretInput("recoveryFlow.confirmPin"), { target: { value: "19472" } });
    await act(async () => {
      fireEvent.click(restoreButton());
    });
    expect(toastError).toHaveBeenCalledTimes(1);
    expect(restore).not.toHaveBeenCalled();
  });
});

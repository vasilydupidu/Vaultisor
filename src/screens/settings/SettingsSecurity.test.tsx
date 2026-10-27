import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
  initReactI18next: { type: "3rdParty", init: () => {} },
}));

const changePin = vi.fn();
const systemCheck = vi.fn();
vi.mock("@/lib/api", () => ({
  apiGetEnableHealthCheck: () => Promise.resolve(true),
  apiGetEnableGenerator: () => Promise.resolve(false),
  apiSetEnableGenerator: vi.fn(),
  apiGetEnablePasswordHistory: () => Promise.resolve(true),
  apiSetEnableHealthCheck: vi.fn(),
  apiSetEnablePasswordHistory: vi.fn(),
  apiGetFido2Status: () => Promise.resolve({ keys: [] }),
  apiRegisterFido2Key: vi.fn(),
  apiUnbindFido2Key: vi.fn(),
  apiOpenSecurityKeySettings: vi.fn(),
  apiVaultChangePin: (...a: unknown[]) => changePin(...a),
  apiSecuritySetHello: vi.fn(),
  apiSecuritySetStepUp: vi.fn(),
  apiSettingsGet: vi.fn(),
  apiSystemCheck: () => systemCheck(),
}));

// Диалог подтверждения PIN: считаем, сколько раз его вызвали.
const authorized = vi.fn(async (_action: string, run: () => Promise<unknown>) => run());
vi.mock("@/components/SecurityConfirm", () => ({
  isAuthCancelled: () => false,
  useSecurityConfirm: () => authorized,
}));

const toastError = vi.fn();
const toastSuccess = vi.fn();
vi.mock("@/components/ui/Toast", () => ({
  useToast: () => ({ error: toastError, success: toastSuccess }),
}));

import { SettingsSecurity } from "./SettingsSecurity";
import type { SettingsDto } from "@/lib/api";

const SETTINGS = {
  use_windows_hello: false,
  require_auth_for_copy: false,
} as SettingsDto;

async function renderSecurity(tpmAvailable: boolean) {
  systemCheck.mockResolvedValue({ tpm_available: tpmAvailable });
  await act(async () => {
    render(<SettingsSecurity s={SETTINGS} onSecurityChanged={() => {}} />);
  });
}

async function submitNewPin(first: string, second = first, tpm = true) {
  fireEvent.change(
    screen.getByPlaceholderText(tpm ? "settingsSecurity.newPinPrompt" : "settingsSecurity.newPassPrompt"),
    { target: { value: first } },
  );
  fireEvent.change(
    screen.getByPlaceholderText(
      tpm ? "settingsSecurity.confirmNewPinPrompt" : "settingsSecurity.confirmNewPassPrompt",
    ),
    { target: { value: second } },
  );
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "settingsSecurity.changePinBtn" }));
  });
}

describe("смена PIN в настройках", () => {
  beforeEach(() => {
    changePin.mockReset();
    systemCheck.mockReset();
    authorized.mockClear();
    toastError.mockReset();
    toastSuccess.mockReset();
  });
  afterEach(cleanup);

  it("неверный формат нового PIN отклоняется до запроса подтверждения", async () => {
    await renderSecurity(true);
    await submitNewPin("12345"); // короче 11
    expect(toastError).toHaveBeenCalledTimes(1);
    expect(authorized).not.toHaveBeenCalled();
    expect(changePin).not.toHaveBeenCalled();
  });

  it("слабый секрет (одна цифра, один символ) тоже отклоняется заранее", async () => {
    await renderSecurity(true);
    await submitNewPin("1".repeat(12));
    await submitNewPin("a".repeat(20));
    expect(toastError).toHaveBeenCalledTimes(2);
    expect(authorized).not.toHaveBeenCalled();
    expect(changePin).not.toHaveBeenCalled();
  });

  it("без TPM короткий PIN не принимается, мастер-пароль с пробелами проходит", async () => {
    await renderSecurity(false);
    await submitNewPin("19472856302", "19472856302", false); // 11 цифр, но нужен пароль ≥15
    expect(authorized).not.toHaveBeenCalled();
    expect(toastError).toHaveBeenCalledTimes(1);

    changePin.mockResolvedValue(undefined);
    await submitNewPin("мой пароль: #1 для сейфа!", "мой пароль: #1 для сейфа!", false);
    expect(authorized).toHaveBeenCalledWith("change_pin", expect.any(Function));
    expect(changePin).toHaveBeenCalledWith("мой пароль: #1 для сейфа!", expect.any(String));
  });

  it("корректный PIN доходит до подтверждения и backend", async () => {
    changePin.mockResolvedValue(undefined);
    await renderSecurity(true);
    await submitNewPin("19472856302");
    expect(authorized).toHaveBeenCalledTimes(1);
    expect(changePin).toHaveBeenCalledWith("19472856302", expect.any(String));
    expect(toastSuccess).toHaveBeenCalledWith("settingsSecurity.changePinSuccess");
  });

  it("несовпадающие значения не доходят ни до проверки, ни до подтверждения", async () => {
    await renderSecurity(true);
    await submitNewPin("19472856302", "19472856303");
    expect(toastError).toHaveBeenCalledWith("settingsSecurity.pinsDoNotMatch");
    expect(authorized).not.toHaveBeenCalled();
  });
});

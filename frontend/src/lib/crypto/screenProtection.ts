export async function setScreenProtection(enabled: boolean): Promise<boolean> {
  try {
    const tauri = typeof window !== "undefined" && (window as any).__TAURI__;
    if (tauri && tauri.core && tauri.core.invoke) {
      return await tauri.core.invoke("set_screen_protection", { enabled });
    }
  } catch (e) {
    console.warn("Screen protection not supported or failed:", e);
  }
  return false;
}

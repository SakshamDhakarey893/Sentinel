#[tauri::command]
fn set_screen_protection(window: tauri::WebviewWindow, enabled: bool) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "user32")]
        extern "system" {
            fn SetWindowDisplayAffinity(hwnd: isize, dwAffinity: u32) -> i32;
        }

        let hwnd = window.hwnd().map_err(|e| e.to_string())?;
        // 0x00000011 = WDA_EXCLUDEFROMCAPTURE (Win10 2004+), 1 = WDA_MONITOR
        let affinity: u32 = if enabled { 0x00000011 } else { 0 };
        let mut res = unsafe { SetWindowDisplayAffinity(hwnd.0 as isize, affinity) };
        if res == 0 && enabled {
            // fallback to WDA_MONITOR
            res = unsafe { SetWindowDisplayAffinity(hwnd.0 as isize, 1) };
        }
        if res == 0 && enabled {
            return Err("Failed to set window display affinity on Windows".into());
        }
    }
    Ok(enabled)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![set_screen_protection])
        .setup(|app| {
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                if let Some(window) = app.get_webview_window("main") {
                    let _ = set_screen_protection(window, true);
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Sentinel");
}

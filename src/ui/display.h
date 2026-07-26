#pragma once

#include <stdbool.h>  // bool

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_BOILERPLATE C_app_boilerplate_14px
#define ICON_APP_HOME        C_home_boilerplate_14px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_BOILERPLATE C_app_boilerplate_64px
#define ICON_APP_HOME        ICON_APP_BOILERPLATE
#define ICON_APP_WARNING     C_Warning_64px
#elif defined(TARGET_APEX_P)
#define ICON_APP_BOILERPLATE C_app_boilerplate_48px
#define ICON_APP_HOME        ICON_APP_BOILERPLATE
#define ICON_APP_WARNING     LARGE_WARNING_ICON
#endif

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

/**
 * Start the streamed review: show who the email is from, to whom, about what,
 * and the attachment descriptor if there is one.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_stream_header(void);

/**
 * Show one slice of the message body as it arrives.
 *
 * @param[in] text    Null-terminated slice, owned by the caller for the page's life.
 * @param[in] is_last Whether this is the final slice (the signing page comes next).
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_stream_body_page(const char *text, bool is_last);


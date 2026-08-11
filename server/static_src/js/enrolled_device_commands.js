// Live updates for the "Last commands" table on the enrolled device detail page.
// Polls a server-rendered fragment, backs off while idle, pauses when the device
// goes quiet (with a Resume affordance), and drives poke / delete.
//
// jQuery is a global (loaded before the bundle); Bootstrap registers its jQuery
// plugins (.tooltip) when it sees window.jQuery, so $.fn.tooltip is available.
// The X-CSRFToken header on unsafe requests is added globally by the $.ajaxSetup
// in base.html, so it is not set here.

export function initEnrolledDeviceCommands() {
    var $list = $("#ed-command-list");
    if (!$list.length) {
        return;  // not on the enrolled device detail page
    }

    var feedUrl = $list.data("feed-url");
    // cadence + limits, tunable via data- attributes on #ed-command-list
    var POLL_INTERVAL = $list.data("poll-interval") || 3000;
    var MAX_POLL_INTERVAL = $list.data("max-poll-interval") || 15000;
    var IDLE_TIMEOUT = $list.data("idle-timeout") || 120000;
    var MAX_ERRORS = $list.data("max-errors") || 3;

    var pollTimeoutId = null;
    var pollInterval = POLL_INTERVAL;  // current interval, grows when idle
    var lastHtml = null;
    var lastChangeAt = 0;
    var errorCount = 0;

    function initTooltips() {
        $list.find("[data-bs-toggle='tooltip']").tooltip();
    }

    function pending() {
        return $list.find(".ed-cmd-pending").data("pending") == 1;
    }

    function setPaused(paused) {
        $("#ed-command-paused").toggleClass("d-none", !paused);
        // while paused, each in-flight row swaps its (now misleading) spinner for a resume button
        $list.find(".cmd-spinner").toggleClass("d-none", paused);
        $list.find(".resume-command").toggleClass("d-none", !paused);
    }

    function setError(msg) {
        if (msg) {
            setPaused(false);  // a hard error supersedes the idle "paused" state
            $("#ed-command-error-msg").text(msg);
            $("#ed-command-error").removeClass("d-none");
        } else {
            $("#ed-command-error").addClass("d-none");
        }
    }

    // call whenever fresh activity is expected (user action, tab focus, observed change)
    function markActivity() {
        lastChangeAt = Date.now();
        pollInterval = POLL_INTERVAL;  // poll fast again
        setPaused(false);
    }

    function schedule() {
        if (pollTimeoutId) {
            window.clearTimeout(pollTimeoutId);
            pollTimeoutId = null;
        }
        // nothing in flight, or paused in the background -> stop (resumes on focus)
        if (document.hidden || !pending()) {
            return;
        }
        // pending but quiet for too long -> the device is likely offline, stop and offer Resume
        if (Date.now() - lastChangeAt > IDLE_TIMEOUT) {
            setPaused(true);
            return;
        }
        pollTimeoutId = window.setTimeout(poll, pollInterval);
    }

    function poll() {
        $.ajax({
            url: feedUrl,
            headers: {"X-Requested-With": "XMLHttpRequest"},
            success: function (html) {
                errorCount = 0;
                setError(null);
                // only touch the DOM (and reset the backoff/idle window) when something changed
                if (html !== lastHtml) {
                    lastHtml = html;
                    lastChangeAt = Date.now();
                    pollInterval = POLL_INTERVAL;  // something changed -> poll fast
                    $list.html(html);
                    initTooltips();
                } else {
                    // nothing changed -> ease off, up to the cap
                    pollInterval = Math.min(pollInterval * 2, MAX_POLL_INTERVAL);
                }
                schedule();
            },
            error: function (xhr) {
                // session/permission lost -> the response is not a usable fragment; stop
                if (xhr.status === 401 || xhr.status === 403) {
                    setError("Your session has expired — reload the page to keep watching.");
                    return;
                }
                // transient failure -> retry a few times, then give up with a clear signal
                errorCount += 1;
                if (errorCount >= MAX_ERRORS) {
                    setError("Lost the connection to the server.");
                    return;
                }
                schedule();
            }
        });
    }

    function resume() {
        errorCount = 0;
        setError(null);
        markActivity();
        poll();
    }

    function deleteCommand($btn) {
        $.ajax({
            url: $btn.data("url"),
            type: "DELETE",
            success: function () {
                $btn.tooltip("hide");
                markActivity();
                poll();
            },
            error: function (xhr) {
                var msg = "The command could not be deleted. Please reload the page.";
                var data = xhr.responseJSON;
                if (Array.isArray(data) && data.length) {
                    msg = data.join(" ");
                } else if (data && data.detail) {
                    msg = data.detail;
                }
                window.alert(msg);
            }
        });
    }

    function pokeDevice($form) {
        var $btn = $form.find("button");
        var btnHtml = $btn.html();
        $btn.tooltip("hide");
        $btn.prop("disabled", true)
            .html('<span class="spinner-border spinner-border-sm" role="status"></span>');
        $.ajax({
            url: $form.attr("action"),
            type: "POST",
            headers: {"X-Requested-With": "XMLHttpRequest"},
            success: function () {
                // the device will check in shortly; start watching the queue afresh
                markActivity();
                poll();
            },
            complete: function () {
                $btn.prop("disabled", false).html(btnHtml);
            }
        });
    }

    // the command list is replaced on every poll, so delegate from the stable parent
    $list.on("click", ".delete-command", function () {
        deleteCommand($(this));
    });
    $list.on("click", ".resume-command", function (event) {
        event.preventDefault();
        resume();
    });
    $("#poke-form").submit(function (event) {
        event.preventDefault();
        pokeDevice($(this));
    });
    $("#ed-command-resume, #ed-command-retry").click(function (event) {
        event.preventDefault();
        resume();
    });
    document.addEventListener("visibilitychange", function () {
        if (!document.hidden && pending()) {
            // coming back into focus is a fresh start, not idle time
            markActivity();
            poll();
        }
    });

    markActivity();
    schedule();
}

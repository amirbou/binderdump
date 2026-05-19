package google.hardware.image;

@VintfStability
@Backing(type="int")
enum ComponentError {
    /**
     * Given command is invalid (user error). For example, incorrect sequence of
     * commands or command not supported with this component type.
     */
    INVALID_COMMAND,
    /**
     * Given param is invalid (user error).
     */
    INVALID_PARAM,
    /**
     * Command did not complete within timeout.
     */
    TIMED_OUT,
    /**
     * Command failed for a reason not listed above.
     */
    FAILURE
}

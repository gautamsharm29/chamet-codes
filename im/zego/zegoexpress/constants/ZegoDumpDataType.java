package im.zego.zegoexpress.constants;

/** Dump data type. */
public enum ZegoDumpDataType {
    /** Audio. */
    AUDIO(0);

    private int value;

    private ZegoDumpDataType(int value) { this.value = value; }

    public int value() { return this.value; }

    public static ZegoDumpDataType getZegoDumpDataType(int value) {
        try {

            if (AUDIO.value == value) {
                return AUDIO;
            }

        } catch (Exception e) {
            throw new RuntimeException("The enumeration cannot be found");
        }
        return null;
    }
}
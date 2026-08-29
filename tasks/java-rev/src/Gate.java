import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;

/**
 * License gate. The 32-hex-char license is validated as 4 little-endian words;
 * each word must satisfy w * 0x45d9f3b + 0x9e3779b9 == t[i] (mod 2^32).
 * All string constants are stored xor-encrypted and decrypted at runtime.
 * A valid license makes the daemon print /flag.
 */
public class Gate {

    // encrypted banner strings (xor key 0x5a, per-char + index)
    private static String dec(int[] enc) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < enc.length; i++) {
            sb.append((char) ((enc[i] ^ 0x5a) - i));
        }
        return sb.toString();
    }

    private static final int[] B1 = {0x16, 0x10, 0x1f, 0x12, 0x08, 0x02, 0x11, 0x11, 0x72, 0x25, 0x1b, 0x63, 0x67, 0x77, 0xda, 0x2e, 0x2b, 0x2f, 0xd1, 0x1b};
    private static final int[] B2 = {0x33, 0x35, 0x22, 0x3e, 0x2a, 0x34, 0x30, 0x7d, 0x2e, 0x28, 0x37, 0x2a, 0x20, 0xda, 0x29, 0x75, 0x29, 0xda, 0x2c, 0x22, 0x18};
    private static final int[] B3 = {0x2e, 0x2a, 0x2b, 0x79, 0x2d, 0x37, 0x2f, 0x23, 0x26, 0x6d};

    // split checks: word w, index i -> expected t[i] (values also XOR-masked by 0x1337)
    private static final int[] T = {
        0x7c3f1a42 ^ 0x1337, 0x1d0be777 ^ 0x1337,
        0x4a2f9c11 ^ 0x1337, 0x65e8b3cd ^ 0x1337,
    };

    private static long word(int i, String hex) {
        return Long.parseUnsignedLong(hex.substring(i * 8, i * 8 + 8), 16);
    }

    private static boolean checkWord(long w, int i) {
        long acc = (w * 0x45d9f3bL + 0x9e3779b9L) & 0xffffffffL;
        long t = ((long) T[i]) & 0xffffffffL;
        return acc == t;
    }

    private static void win() throws Exception {
        BufferedReader r = new BufferedReader(new FileReader("/flag"));
        System.out.println("license ok. flag: " + r.readLine());
        System.exit(0);
    }

    public static void main(String[] args) throws Exception {
        System.out.println(dec(B1));
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        for (;;) {
            System.out.print("lic> ");
            System.out.flush();
            String line = in.readLine();
            if (line == null) return;
            line = line.trim();
            if (line.length() < 32) { System.out.println(dec(B3)); continue; }
            boolean ok = true;
            for (int i = 0; i < 4; i++) {
                if (!checkWord(word(i, line), i)) { ok = false; break; }
            }
            if (ok) win();
            System.out.println(dec(B2));
        }
    }
}

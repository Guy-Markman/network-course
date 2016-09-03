import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;

public class CalcServer {

    private static interface Op {
        int execute(int a, int b);
    }

    private static Map<String, Op> OPS = new HashMap<String, Op>() {{
        put(
            "+",
            new Op() {
                @Override
                public int execute(int a, int b) {
                    return a + b;
                }
            }
        );
        put(
            "-",
            new Op() {
                @Override
                public int execute(int a, int b) {
                    return a - b;
                }
            }
        );
        put(
            "*",
            new Op() {
                @Override
                public int execute(int a, int b) {
                    return a * b;
                }
            }
        );
        put(
            "/",
            new Op() {
                @Override
                public int execute(int a, int b) {
                    return a / b;
                }
            }
        );
    }};

    // Number with 5 digits, space, operator, number with 5 digits
    private static Pattern EXP_PATTERN = Pattern.compile(
        "^" +
        "(?<num1>\\d{1,5})" +
        "\\s" +
        "(?<op>[+-/*])" +
        "\\s" +
        "(?<num2>\\d{1,5})" +
        "$"
    );

    private static final InetAddress BIND_ADDRESS = null;
    private static final int BIND_PORT = 8001;
    private static final int MAX_TIMEOUT = 60 * 1000;
    private static final String TOKEN_EXIT = "EXIT";

    private static int int_range(int n) {
        final int MIN = 0;
        final int MAX = 65535;
        if (n < MIN) {
            throw new RuntimeException(String.format("Integer '%s' smaller than '%s'", n, MIN));
        }
        if (n > MAX) {
            throw new RuntimeException(String.format("Integer '%s' larger than '%s'", n, MAX));
        }
        return n;
    }

    /*
     * We cannot use BufferedReader.getLine() as it does not
     * have limitation, see JDK-4107821[1].
     * [1] http://bugs.java.com/bugdatabase/view_bug.do?bug_id=4107821
     */
    public static String getLine(InputStream in) throws IOException {
        StringBuilder ret = new StringBuilder();
        int n;

        while (true) {
            n = in.read();
            if (n == -1) {
                throw new RuntimeException("Disconnect");
            }
            if ((char)n == '\n') {
                break;
            }
            ret.append((char)n);
        }
        return ret.toString();
    }

    public static void main(String... args) throws Exception {
        try (ServerSocket sl = new ServerSocket(BIND_PORT, 1, BIND_ADDRESS)) {
            while (true) {
                try (
                    Socket s = sl.accept();
                    PrintWriter out = new PrintWriter(s.getOutputStream(), true);
                    InputStream in = s.getInputStream();
                ) {
                    try {
                        s.setSoTimeout(MAX_TIMEOUT);
                        while (true) {
                            String line = getLine(in);
                            if (TOKEN_EXIT.equals(line)) {
                                break;
                            }
                            try {
                                Matcher m = EXP_PATTERN.matcher(line);
                                if (!m.matches()) {
                                    throw new RuntimeException("Invalid expression");
                                }
                                out.println(
                                    OPS.get(m.group("op")).execute(
                                        int_range(Integer.valueOf(m.group("num1"))),
                                        int_range(Integer.valueOf(m.group("num2")))
                                    )
                                );
                            } catch (Exception e) {
                                out.println(String.format("Error: %s", e.getMessage()));
                            }
                        }
                    } catch (Exception e) {
                        System.out.println(String.format("Error: %s", e.getMessage()));
                        out.println(String.format("Error: %s", e.getMessage()));
                    }
                }
            }
        }
    }
}

// vim: expandtab tabstop=4 shiftwidth=4

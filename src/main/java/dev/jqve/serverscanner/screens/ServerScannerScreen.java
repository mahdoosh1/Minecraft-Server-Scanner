package dev.jqve.serverscanner.screens;

import dev.jqve.serverscanner.mixin.MultiplayerScreenInvoker;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.screen.multiplayer.MultiplayerScreen;
import net.minecraft.client.gui.tooltip.Tooltip;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.client.gui.widget.TextFieldWidget;
import net.minecraft.client.network.ServerInfo;
import net.minecraft.client.option.ServerList;
import net.minecraft.text.Text;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * ServerScannerScreen with scrollable server list
 * and user-configurable CIDR subnet prefix (default 24).
 */
public class ServerScannerScreen extends Screen {
    private static final Logger LOGGER = LogManager.getLogger(ServerScannerScreen.class);

    /* ---------- CONFIG ---------- */
    private static final int    TIMEOUT_MS         = 200;
    private static final int    THREAD_POOL_SIZE   = 50;
    private static final int    DEFAULT_MINECRAFT_PORT = 25565;
    private static final int    DEFAULT_SUBNET_PREFIX  = 24;

    /* ---------- UI CONSTANTS ---------- */
    private static final int BUTTON_HEIGHT   = 20;
    private static final int BUTTON_SPACING  = 4;
    private static final int RESULTS_START_Y = 120;

    private static final int IP_FIELD_WIDTH     = 150;
    private static final int SUBNET_FIELD_WIDTH = 45;
    private static final int FIELD_GAP          = 5;

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    /* ---------- FIELDS ---------- */
    private final Screen parent;
    private final Set<ServerInfo> foundServers = Collections.synchronizedSet(new LinkedHashSet<>());
    private final Queue<Runnable> uiUpdateQueue = new ConcurrentLinkedQueue<>();
    private final List<ButtonWidget> serverButtons = new ArrayList<>();

    private TextFieldWidget ipTextField;
    private TextFieldWidget subnetTextField;
    private ButtonWidget scanButton;
    private Text statusText;
    private ExecutorService executorService;
    private ScheduledExecutorService uiUpdateExecutor;
    private volatile boolean isScanning;

    /* ---------- STATE PERSISTENCE ---------- */
    private String savedIpText   = "";
    private String savedSubnetText = "";

    /* ---------- LAYOUT HELPERS ---------- */
    private int buttonsPerRow;
    private int dynamicButtonWidth;
    private static final int MAX_VISIBLE_ROWS = 2;
    private int totalRows;
    private int scrollOffset = 0;
    private final int scrollSpeed = 10;

    public ServerScannerScreen(Screen parent) {
        super(Text.literal("Minecraft Server Scanner"));
        this.parent = parent;
    }

    /* ================================================================ */
    /* =====================   INIT / LIFECYCLE   ===================== */
    /* ================================================================ */

    @Override
    protected void init() {
        saveCurrentState();
        calculateLayoutMetrics();
        initializeTextFields();
        initializeButtons();
        restoreState();
        startUiUpdateThread();
    }

    private void calculateLayoutMetrics() {
        int totalWidth = Math.max(1, this.width - 40);
        int approxButtonWidth = 180;
        buttonsPerRow = Math.max(1, totalWidth / (approxButtonWidth + BUTTON_SPACING));
        int spaceForButtons = totalWidth - (BUTTON_SPACING * (buttonsPerRow - 1));
        dynamicButtonWidth = Math.max(50, spaceForButtons / buttonsPerRow);
    }

    private void saveCurrentState() {
        if (this.ipTextField != null) {
            this.savedIpText   = this.ipTextField.getText();
            this.savedSubnetText = this.subnetTextField.getText();
        }
    }

    private void initializeTextFields() {
        int y = 20;
        int centerX = this.width / 2;
        int comboWidth = IP_FIELD_WIDTH + FIELD_GAP + SUBNET_FIELD_WIDTH;
        int startX = centerX - comboWidth / 2;

        this.ipTextField = new TextFieldWidget(textRenderer, startX, y,
                IP_FIELD_WIDTH, BUTTON_HEIGHT, Text.literal("IP Address"));
        this.ipTextField.setMaxLength(15);
        this.ipTextField.setTooltip(Tooltip.of(Text.literal("Enter IP address (e.g. 192.168.1.1)")));

        this.subnetTextField = new TextFieldWidget(textRenderer,
                startX + IP_FIELD_WIDTH + FIELD_GAP, y,
                SUBNET_FIELD_WIDTH, BUTTON_HEIGHT, Text.literal("/"));
        this.subnetTextField.setMaxLength(2);
        this.subnetTextField.setTooltip(Tooltip.of(Text.literal("CIDR prefix")));
        this.subnetTextField.setText(String.valueOf(DEFAULT_SUBNET_PREFIX));

        this.addDrawableChild(ipTextField);
        this.addDrawableChild(subnetTextField);
    }

    private void initializeButtons() {
        this.scanButton = ButtonWidget.builder(Text.literal("Scan Network"), this::handleScanButton)
                .width(200)
                .position(this.width / 2 - 100, 50)
                .build();

        ButtonWidget backButton = ButtonWidget.builder(Text.literal("Back"),
                button -> MinecraftClient.getInstance().setScreen(parent))
                .width(50)
                .position(5, 5)
                .build();

        this.addDrawableChild(scanButton);
        this.addDrawableChild(backButton);
    }

    private void restoreState() {
        statusText = Text.literal("");
        this.ipTextField.setText(this.savedIpText.isEmpty()   ? "192.168.1.1" : this.savedIpText);
        this.subnetTextField.setText(this.savedSubnetText.isEmpty()
                ? String.valueOf(DEFAULT_SUBNET_PREFIX) : this.savedSubnetText);
    }

    private void startUiUpdateThread() {
        uiUpdateExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "UI-Update-Thread");
            t.setDaemon(true);
            return t;
        });
        uiUpdateExecutor.scheduleAtFixedRate(() -> {
            while (!uiUpdateQueue.isEmpty()) {
                Runnable update = uiUpdateQueue.poll();
                if (update != null) {
                    MinecraftClient.getInstance().execute(update);
                }
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
    }

    /* ================================================================ */
    /* ========================   SCAN LOGIC   ======================== */
    /* ================================================================ */

    private int getSubnetPrefix() {
        try {
            return Integer.parseInt(subnetTextField.getText().trim());
        } catch (NumberFormatException ex) {
            return DEFAULT_SUBNET_PREFIX;
        }
    }

    private void handleScanButton(ButtonWidget button) {
        if (isScanning) stopScanning(); else startScanning();
    }

    private void startScanning() {
        String ip = ipTextField.getText().trim();
        if (!validateInput(ip)) return;

        isScanning = true;
        foundServers.clear();
        clearServerButtons();

        queueUiUpdate(() -> {
            scanButton.setMessage(Text.literal("Stop Scanning"));
            updateServerList();
        });

        executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE, r -> {
            Thread thread = new Thread(r, "Server-Scanner-Thread");
            thread.setDaemon(true);
            return thread;
        });

        scanNetwork(ip);
    }

    private void stopScanning() {
        if (executorService != null) {
            executorService.shutdownNow();
            executorService = null;
        }
        isScanning = false;

        queueUiUpdate(() -> {
            scanButton.setMessage(Text.literal("Scan Network"));
            statusText = Text.literal("§cScanning stopped");
        });
    }

    private boolean validateInput(String ip) {
        if (!IP_PATTERN.matcher(ip).matches()) {
            setStatusText("§cInvalid IP address format");
            return false;
        }
        return true;
    }

    private void scanNetwork(String literalIp) {
        final int prefix = Math.max(1, Math.min(30, getSubnetPrefix()));
        final int hostBits = 32 - prefix;
        final int totalHosts = (1 << hostBits) - 2;
        if (totalHosts <= 0) {
            setStatusText("§cPrefix too large (no usable hosts)");
            completeScan();
            return;
        }

        AtomicInteger processed = new AtomicInteger(0);

        /* numeric network base */
        int net;
        try {
            byte[] b = InetAddress.getByName(literalIp).getAddress();
            net = ((b[0] & 0xFF) << 24) |
                  ((b[1] & 0xFF) << 16) |
                  ((b[2] & 0xFF) << 8)  |
                   (b[3] & 0xFF);
        } catch (Exception e) {
            setStatusText("§cCannot resolve IP");
            completeScan();
            return;
        }

        final int mask = 0xFFFFFFFF << hostBits;
        final int network = net & mask;

        /* schedule scan tasks */
        for (int host = 1; host <= totalHosts && isScanning; host++) {
            final int ipInt = network + host;
            final String ipStr = String.format("%d.%d.%d.%d",
                    (ipInt >>> 24) & 0xFF,
                    (ipInt >>> 16) & 0xFF,
                    (ipInt >>> 8)  & 0xFF,
                    ipInt & 0xFF);

            CompletableFuture.runAsync(() -> {
                if (isPortOpen(ipStr)) {
                    ServerInfo s = new ServerInfo(
                            "Server #" + ipStr,
                            ipStr + ":" + DEFAULT_MINECRAFT_PORT,
                            ServerInfo.ServerType.LAN);
                    foundServers.add(s);
                    LOGGER.info("Found server at {}", ipStr);
                    queueUiUpdate(this::updateServerList);
                }
                int p = processed.incrementAndGet();
                updateProgress(p, totalHosts);
            }, executorService);
        }
        stopScanning();
        completeScan();
    }

    private boolean isPortOpen(String ip) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ip, DEFAULT_MINECRAFT_PORT), TIMEOUT_MS);
            return true;
        } catch (IOException ignored) {
            return false;
        }
    }

    private void updateProgress(int processed, int total) {
        float pct = (float) processed / total * 100;
        setStatusText(String.format("§eScanning: %.1f%% (%d/%d)", pct, processed, total));
    }

    private void completeScan() {
        if (!isScanning) return;
        queueUiUpdate(() -> {
            isScanning = false;
            scanButton.setMessage(Text.literal("Scan Network"));
            statusText = Text.literal("§aScan complete! Found " + foundServers.size() + " servers");
            updateServerList();
        });
    }

    private void clearServerButtons() {
        for (ButtonWidget button : serverButtons) {
            this.remove(button);
        }
        serverButtons.clear();
    }

    /* ================================================================ */
    /* ========================   UI UTILS   ========================== */
    /* ================================================================ */

    private void updateServerList() {
        clearServerButtons();
        if (foundServers.isEmpty()) return;

        int serverCount = foundServers.size();
        totalRows = (int) Math.ceil((double) serverCount / buttonsPerRow);
        int idx = 0;
        int yStart = RESULTS_START_Y - scrollOffset;

        for (ServerInfo server : foundServers) {
            int row = idx / buttonsPerRow;
            int col = idx % buttonsPerRow;
            int buttonY = yStart + row * (BUTTON_HEIGHT + BUTTON_SPACING);
            int buttonX = 20 + col * (dynamicButtonWidth + BUTTON_SPACING);

            ButtonWidget btn = ButtonWidget.builder(Text.literal(server.name),
                            b -> addServerToList(server))
                    .width(dynamicButtonWidth)
                    .position(buttonX, buttonY)
                    .build();
            this.serverButtons.add(btn);
            this.addDrawableChild(btn);
            idx++;
        }
    }

    private void addServerToList(ServerInfo server) {
        MinecraftClient client = MinecraftClient.getInstance();
        MultiplayerScreen mp = new MultiplayerScreen(this);
        mp.init(client, this.width, this.height);

        ServerList list = new ServerList(client);
        list.loadFile();

        MultiplayerScreenInvoker inv = (MultiplayerScreenInvoker) mp;
        inv.setServerList(list);
        inv.setSelectedEntry(server);
        inv.invokeAddEntry(true);

        client.setScreen(this);
        foundServers.remove(server);
        updateServerList();
    }

    private void queueUiUpdate(Runnable update) {
        uiUpdateQueue.offer(update);
    }

    private void setStatusText(String message) {
        queueUiUpdate(() -> statusText = Text.literal(message));
    }

    /* ================================================================ */
    /* =====================   SCROLL HANDLING   ====================== */
    /* ================================================================ */

    public boolean mouseScrolled(double mouseX, double mouseY, double amount) {
        int maxRowsVisible = MAX_VISIBLE_ROWS;
        if (totalRows > maxRowsVisible) {
            int totalHeight = totalRows * (BUTTON_HEIGHT + BUTTON_SPACING);
            int maxVisibleHeight = maxRowsVisible * (BUTTON_HEIGHT + BUTTON_SPACING);
            int maxScroll = Math.max(0, totalHeight - maxVisibleHeight);

            scrollOffset -= amount * scrollSpeed;
            scrollOffset = Math.max(0, Math.min(maxScroll, scrollOffset));

            updateServerList();
        }
        return super.mouseScrolled(mouseX, mouseY, amount, amount);
    }

    /* ================================================================ */
    /* ========================   RENDER   ============================ */
    /* ================================================================ */

    @Override
    public void render(DrawContext ctx, int mx, int my, float delta) {
        this.renderBackground(ctx, mx, my, delta);
        super.render(ctx, mx, my, delta);

        ctx.drawTextWithShadow(this.textRenderer, title,
                this.width / 2 - this.textRenderer.getWidth(title) / 2, 5, 0xFFFFFF);

        if (statusText != null) {
            ctx.drawTextWithShadow(this.textRenderer, statusText,
                    this.width / 2 - this.textRenderer.getWidth(statusText) / 2, 80, 0xFFFFFF);
        }
    }

    /* ================================================================ */
    /* ======================   SHUTDOWN   ============================ */
    /* ================================================================ */

    @Override
    public void removed() {
        stopScanning();
        if (uiUpdateExecutor != null) {
            uiUpdateExecutor.shutdownNow();
            uiUpdateExecutor = null;
        }
        super.removed();
    }

    @Override
    public void resize(MinecraftClient client, int width, int height) {
        String ip  = this.ipTextField   != null ? this.ipTextField.getText()   : "";
        String sub = this.subnetTextField != null ? this.subnetTextField.getText() : "";
        init(client, width, height);
        this.ipTextField.setText(ip);
        this.subnetTextField.setText(sub);
        updateServerList();
    }
}

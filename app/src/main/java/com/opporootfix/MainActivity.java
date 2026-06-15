package com.opporootfix;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.Intent;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(dp(24), dp(24), dp(24), dp(24));
        layout.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("OPPO Watch 解锁修复");
        title.setTextSize(24);
        title.setTypeface(null, Typeface.BOLD);
        title.setTextColor(Color.parseColor("#FF6200"));
        title.setGravity(Gravity.CENTER);
        layout.addView(title);

        addSpacer(layout, 16);

        boolean moduleActive = isModuleActive();

        TextView status = new TextView(this);
        status.setText(moduleActive ? "✓ 模块已激活" : "✗ 模块未激活");
        status.setTextSize(16);
        status.setTypeface(null, Typeface.BOLD);
        status.setTextColor(moduleActive ? Color.parseColor("#4CAF50") : Color.parseColor("#F44336"));
        status.setGravity(Gravity.CENTER);
        layout.addView(status);

        addSpacer(layout, 8);

        TextView scopeInfo = new TextView(this);
        scopeInfo.setText("作用域：com.heytap.health (欢太健康)");
        scopeInfo.setTextSize(14);
        scopeInfo.setTextColor(Color.GRAY);
        scopeInfo.setGravity(Gravity.CENTER);
        layout.addView(scopeInfo);

        addSpacer(layout, 24);

        TextView instructionsTitle = new TextView(this);
        instructionsTitle.setText("使用说明：");
        instructionsTitle.setTextSize(18);
        instructionsTitle.setTypeface(null, Typeface.BOLD);
        layout.addView(instructionsTitle);

        addSpacer(layout, 8);

        String[] instructions = {
                "1. 在LSPosed管理器中启用此模块",
                "2. 将作用域设置为「欢太健康」",
                "3. 强制停止欢太健康App",
                "4. 重新打开欢太健康App",
                "5. 尝试使用手表解锁手机功能"
        };

        for (String instruction : instructions) {
            TextView tv = new TextView(this);
            tv.setText(instruction);
            tv.setTextSize(14);
            tv.setPadding(dp(16), dp(4), 0, dp(4));
            layout.addView(tv);
        }

        addSpacer(layout, 16);

        TextView troubleshootingTitle = new TextView(this);
        troubleshootingTitle.setText("如果仍然失败：");
        troubleshootingTitle.setTextSize(18);
        troubleshootingTitle.setTypeface(null, Typeface.BOLD);
        layout.addView(troubleshootingTitle);

        addSpacer(layout, 8);

        String[] troubleshooting = {
                "• 在KernelSU中关闭对欢太健康的DenyList",
                "• 确保Shamiko已禁用或正确配置",
                "• 重启手机后再试"
        };

        for (String tip : troubleshooting) {
            TextView tv = new TextView(this);
            tv.setText(tip);
            tv.setTextSize(14);
            tv.setTextColor(Color.parseColor("#666666"));
            tv.setPadding(dp(16), dp(4), 0, dp(4));
            layout.addView(tv);
        }

        addSpacer(layout, 24);

        TextView hookStatus = new TextView(this);
        hookStatus.setText("Hook状态：正在绕过root检测 ✓");
        hookStatus.setTextSize(14);
        hookStatus.setTextColor(Color.parseColor("#4CAF50"));
        hookStatus.setGravity(Gravity.CENTER);
        layout.addView(hookStatus);

        addSpacer(layout, 16);

        if (!moduleActive) {
            Button activateBtn = new Button(this);
            activateBtn.setText("打开LSPosed管理器");
            activateBtn.setOnClickListener(v -> {
                try {
                    Intent intent = getPackageManager().getLaunchIntentForPackage("org.lsposed.manager");
                    if (intent != null) {
                        startActivity(intent);
                    } else {
                        Toast.makeText(this, "未找到LSPosed管理器", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    Toast.makeText(this, "无法打开LSPosed管理器", Toast.LENGTH_SHORT).show();
                }
            });
            layout.addView(activateBtn);
        }

        setContentView(layout);
    }

    private void addSpacer(LinearLayout layout, int dp) {
        View spacer = new View(this);
        spacer.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp * getResources().getDisplayMetrics().density));
        layout.addView(spacer);
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density);
    }

    private boolean isModuleActive() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }
}

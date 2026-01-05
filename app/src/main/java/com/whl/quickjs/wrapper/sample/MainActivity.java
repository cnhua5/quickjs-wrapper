package com.whl.quickjs.wrapper.sample;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.whl.quickjs.android.QuickJSLoader;
import com.whl.quickjs.wrapper.JSCrypto;
import com.whl.quickjs.wrapper.QuickJSContext;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "QuickJS";
    QuickJSContext jsContext;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        QuickJSLoader.init();

        jsContext = QuickJSContext.create();
        jsContext.evaluate("var text = 'Hello sjw';");
        jsContext.evaluate("var pid = native.syscall(1);");
        String text = jsContext.getGlobalObject().getString("text");
        long pid = jsContext.getGlobalObject().getInteger("pid");


        String sensitiveJS = "var secret = 'This is encrypted code!';\n" +
                             "var result = 1 + 2 + 3;\n" +
                             "secret + ' Result: ' + result;";
        
        byte[] encryptedData = JSCrypto.encrypt(sensitiveJS);

        Object encryptedResult = jsContext.executeEncrypted(encryptedData, "secret.js");

        byte[] customKey = JSCrypto.generateKey(32);

        TextView textView = findViewById(R.id.text);
        textView.setText("normal:\n" +
                        "  text = " + text + "\n" +
                        "  pid = " + pid + "\n\n" +
                        "encry:\n" +
                        "  " + encryptedResult);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        jsContext.destroy();
    }
}
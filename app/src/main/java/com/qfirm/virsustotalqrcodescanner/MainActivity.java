package com.qfirm.virsustotalqrcodescanner;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.camera.core.Camera;
import androidx.camera.core.CameraSelector;
import androidx.camera.core.ImageAnalysis;
import androidx.camera.core.Preview;
import androidx.camera.lifecycle.ProcessCameraProvider;
import androidx.camera.view.PreviewView;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.LifecycleOwner;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.util.Size;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.common.util.concurrent.ListenableFuture;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

import java.io.UnsupportedEncodingException;
import java.util.concurrent.ExecutionException;


public class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_CAMERA = 0;

    private PreviewView previewView;
    private ListenableFuture<ProcessCameraProvider> cameraProviderFuture;

    private Button qrCodeFoundButton;
    private String qrCode;
    private String qrCodeResponse;
    private int thePositives =0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        //set appTitle
        ActionBar actionBar = getSupportActionBar();//getbetter name

        actionBar.setDisplayShowHomeEnabled(true);
        actionBar.setIcon(R.drawable.logoname);

        ColorDrawable colorDrawable
                = new ColorDrawable(Color.parseColor("#000000"));

        // Set BackgroundDrawable
        actionBar.setBackgroundDrawable(colorDrawable);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        previewView = findViewById(R.id.activity_main_previewView);

        qrCodeFoundButton = findViewById(R.id.activity_main_qrCodeFoundButton);
        qrCodeFoundButton.setVisibility(View.INVISIBLE);
        qrCodeFoundButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new FetchURLData().execute();
            }
        });

        cameraProviderFuture = ProcessCameraProvider.getInstance(this);
        requestCamera();
    }

    private void requestCamera() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            startCamera();
        } else {
            if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.CAMERA)) {
                ActivityCompat.requestPermissions(MainActivity.this, new String[]{Manifest.permission.CAMERA}, PERMISSION_REQUEST_CAMERA);
            } else {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, PERMISSION_REQUEST_CAMERA);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        if (requestCode == PERMISSION_REQUEST_CAMERA) {
            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startCamera();
            } else {
                Toast.makeText(this, "Camera Permission Denied", Toast.LENGTH_SHORT).show();
            }
        }
    }

    private void startCamera() {
        cameraProviderFuture.addListener(() -> {
            try {
                ProcessCameraProvider cameraProvider = cameraProviderFuture.get();
                bindCameraPreview(cameraProvider);
            } catch (ExecutionException | InterruptedException e) {
                Toast.makeText(this, "Error starting camera " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }, ContextCompat.getMainExecutor(this));
    }

    private void bindCameraPreview(@NonNull ProcessCameraProvider cameraProvider) {
        previewView.setPreferredImplementationMode(PreviewView.ImplementationMode.SURFACE_VIEW);

        Preview preview = new Preview.Builder()
                .build();

        CameraSelector cameraSelector = new CameraSelector.Builder()
                .requireLensFacing(CameraSelector.LENS_FACING_BACK)
                .build();

        preview.setSurfaceProvider(previewView.createSurfaceProvider());

        ImageAnalysis imageAnalysis =
                new ImageAnalysis.Builder()
                        .setTargetResolution(new Size(1280, 720))
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build();

        imageAnalysis.setAnalyzer(ContextCompat.getMainExecutor(this), new QRCodeImageAnalyzer(new QRCodeFoundListener() {
            @Override
            public void onQRCodeFound(String _qrCode) {
                qrCode = _qrCode;
                qrCodeFoundButton.setVisibility(View.VISIBLE);
            }

            @Override
            public void qrCodeNotFound() {
                qrCodeFoundButton.setVisibility(View.INVISIBLE);
            }
        }));

        Camera camera = cameraProvider.bindToLifecycle((LifecycleOwner)this, cameraSelector, imageAnalysis, preview);
    }

    private class FetchURLData extends AsyncTask<Void, Void, String> {
        @Override
        protected String doInBackground(Void... params) {

            // Will contain the raw JSON response as a string.
            String stringResults = null;
            try {
                VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKey");//need to put in APIKey to make it work
                VirustotalPublicV2 virusTotalRef;
                virusTotalRef = new VirustotalPublicV2Impl();
                String urls[] = {qrCode};
                String theReport[] = {""};

                ScanInfo[] scanInfoArr = virusTotalRef.scanUrls(urls);
                FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);
                for (FileScanReport report : reports) {
                    if(report.getResponseCode()==0){
                        continue;
                    }
                    thePositives = report.getPositives();
                    if( thePositives> 0)
                        qrCodeResponse = qrCode +" has at least one malicious report";
                    else
                        qrCodeResponse = qrCode +" has no malicious reports";
                    stringResults = qrCodeResponse;

                }

                // Construct the URL for the OpenWeatherMap query
                // Possible parameters are avaiable at OWM's forecast API page, at
                // http://openweathermap.org/API#forecast

                return stringResults;
            } catch (APIKeyNotFoundException ex) {
                System.err.println("API Key not found! " + ex.getMessage());
            } catch (UnsupportedEncodingException ex) {
                System.err.println("Unsupported Encoding Format!" + ex.getMessage());
            } catch (UnauthorizedAccessException ex) {
                System.err.println("Invalid API Key " + ex.getMessage());
            } catch (Exception ex) {
                System.err.println("Something Bad Happened! " + ex.getMessage());
            }

        return stringResults; }



        @Override
        protected void onPostExecute(String s) {
            super.onPostExecute(s);
           //


           // Show warning message with custom toast message with image
            ImageView view = new ImageView(getApplicationContext());
            LayoutInflater inflater = getLayoutInflater();
            View layout = inflater.inflate(R.layout.custom_toast_layout,(ViewGroup) findViewById(R.id.toast_layout_root));


            TextView txt = (TextView) layout.findViewById(R.id.toastmsg);
            txt.setText(qrCodeResponse);

            ImageView image = (ImageView) layout.findViewById(R.id.image);
            if(thePositives >0)
                image.setImageResource(R.drawable.warning);
            else
                image.setImageResource(R.drawable.check);


            Toast toast = new Toast(getApplicationContext());
            toast.setGravity(Gravity.BOTTOM,0, 0);
            toast.setDuration(Toast.LENGTH_LONG);
            toast.setView(layout);
            toast.show();

            Log.i(MainActivity.class.getSimpleName(), "QR Code Found: " + qrCode);
        }
    }


}


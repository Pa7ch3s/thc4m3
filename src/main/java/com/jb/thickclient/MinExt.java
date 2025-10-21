package com.jb.thickclient;
import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class MinExt implements IBurpExtender {
  @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks cb) {
    cb.setExtensionName("THC4M3 (Safe Load)");
  }
}

import Cocoa
import FlutterMacOS

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    self.contentViewController = flutterViewController

    let defaultWidth: CGFloat = 1280
    let defaultHeight: CGFloat = 820
    self.minSize = NSSize(width: 960, height: 640)
    if let screenFrame = (self.screen ?? NSScreen.main)?.visibleFrame {
      let width = min(defaultWidth, screenFrame.width)
      let height = min(defaultHeight, screenFrame.height)
      let originX = screenFrame.origin.x + (screenFrame.width - width) / 2.0
      let originY = screenFrame.origin.y + (screenFrame.height - height) / 2.0
      self.setFrame(NSRect(x: originX, y: originY, width: width, height: height), display: true)
    } else {
      self.setFrame(NSRect(x: 0, y: 0, width: defaultWidth, height: defaultHeight), display: true)
      self.center()
    }

    let channel = FlutterMethodChannel(
      name: "maprisma/window",
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )
    channel.setMethodCallHandler { [weak self] call, result in
      if call.method == "titlebar" {
        if let mode = call.arguments as? String {
          switch mode {
          case "dark":
            self?.appearance = NSAppearance(named: .darkAqua)
          case "light":
            self?.appearance = NSAppearance(named: .aqua)
          default:
            self?.appearance = nil
          }
        }
        result(nil)
      } else if call.method == "tiled" {
        result(false)
      } else {
        result(FlutterMethodNotImplemented)
      }
    }

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}

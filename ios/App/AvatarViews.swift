import PassAuthKit
import PhotosUI
import SwiftUI
import UIKit

/// An account's avatar: its profile picture when this device has it, else its initials.
struct AccountAvatar: View {
    @Environment(AppModel.self) private var model
    let id: String
    let name: String
    let email: String
    var size: CGFloat = 32

    var body: some View {
        Avatar(text: initials(name, email), size: size, image: model.repo.avatars[id].flatMap(Self.image))
    }

    static func image(_ jpeg: Data) -> Image? { UIImage(data: jpeg).map { Image(uiImage: $0) } }
}

/// The Account page's big avatar. Where the server has profile pictures it is a button:
/// Choose photo… (Photos picker; the picture is cropped, resized and re-encoded on the device
/// before it is sealed and sent) and Remove photo (only when one is set).
struct AccountPageAvatar: View {
    @Environment(AppModel.self) private var model
    var size: CGFloat = 72
    @State private var askAction = false
    @State private var picking = false
    @State private var picked: PhotosPickerItem?
    @State private var busy = false

    var body: some View {
        let s = model.state
        let hasPicture = model.repo.activeAvatar != nil
        if model.repo.avatarsSupported && s.status == .unlocked {
            Button {
                if hasPicture { askAction = true } else { picking = true }
            } label: {
                AccountAvatar(id: s.activeId, name: s.name, email: s.email, size: size)
                    .overlay {
                        if busy {
                            Circle().fill(.black.opacity(0.35))
                            ProgressView().tint(.white)
                        }
                    }
                    .overlay(alignment: .bottomTrailing) {
                        Image(systemName: "camera.fill")
                            .font(.system(size: size * 0.16, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(width: size * 0.34, height: size * 0.34)
                            .background(Color.paAccentFill, in: Circle())
                            .overlay(Circle().stroke(Color.paBackground, lineWidth: 2))
                    }
            }
            .buttonStyle(.plain)
            .disabled(busy)
            .accessibilityLabel(hasPicture ? "Change profile picture" : "Add profile picture")
            .accessibilityIdentifier("account.avatar")
            .confirmationDialog("Profile picture", isPresented: $askAction, titleVisibility: .hidden) {
                Button("Choose photo…") { picking = true }
                Button("Remove photo", role: .destructive) { remove() }
                Button("Cancel", role: .cancel) {}
            }
            .photosPicker(isPresented: $picking, selection: $picked, matching: .images, preferredItemEncoding: .compatible)
            .onChange(of: picked) { _, item in
                guard let item else { return }
                picked = nil
                upload(item)
            }
        } else {
            AccountAvatar(id: s.activeId, name: s.name, email: s.email, size: size)
        }
    }

    private func upload(_ item: PhotosPickerItem) {
        busy = true
        model.run {
            defer { busy = false }
            guard let data = try await item.loadTransferable(type: Data.self) else {
                throw UserError("PassAuth couldn't read this photo. Choose another one.")
            }
            let jpeg = await Task.detached(priority: .userInitiated) { AvatarImage.prepare(data) }.value
            guard let jpeg else { throw UserError("PassAuth couldn't read this photo. Choose another one.") }
            try await model.repo.setAvatar(jpeg)
            model.notify("Profile picture updated.")
        }
    }

    private func remove() {
        busy = true
        model.run {
            defer { busy = false }
            try await model.repo.removeAvatar()
            model.notify("Profile picture removed.")
        }
    }
}

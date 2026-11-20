package io.passauth.app.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import io.passauth.app.graph

/**
 * FCM messages from the PassAuth push relay. They are data-only (`{"kind":"auth_request"}`, high
 * priority), so PassAuth always posts the notification itself (Android lowers the priority of apps
 * that get high-priority messages and show nothing). The message carries no account data.
 */
class PassAuthMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        graph.push.received(message.data)
    }

    override fun onNewToken(token: String) {
        graph.push.newToken(token)
    }
}

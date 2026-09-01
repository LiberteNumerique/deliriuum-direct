#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

static NSString * const DeliriuumProviderBundleIdentifier =
    @"com.deliriuum.direct.PacketTunnel";

static NETunnelProviderManager *DeliriuumManager = nil;

static void set_error(char *buffer, size_t buffer_len, NSString *message)
{
    if (buffer == NULL || buffer_len == 0) {
        return;
    }

    const char *text = [message UTF8String];
    if (text == NULL) {
        buffer[0] = '\0';
        return;
    }

    snprintf(buffer, buffer_len, "%s", text);
}

int deliriuum_vpn_up(
    const char *config,
    char *error_buffer,
    size_t error_buffer_len
) {
    @autoreleasepool {
        if (config == NULL) {
            set_error(error_buffer, error_buffer_len, @"Configuration VPN absente.");
            return -1;
        }

        NSString *wireguardConfig =
            [NSString stringWithUTF8String:config];

        if (wireguardConfig == nil) {
            set_error(error_buffer, error_buffer_len, @"Configuration VPN invalide.");
            return -1;
        }

        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

        __block int result = -1;
        __block NSString *failure = nil;

        [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:
         ^(NSArray<NETunnelProviderManager *> *managers, NSError *error) {

            if (error != nil) {
                failure = error.localizedDescription;
                dispatch_semaphore_signal(semaphore);
                return;
            }

            NETunnelProviderManager *manager = nil;

            for (NETunnelProviderManager *candidate in managers) {
                NETunnelProviderProtocol *protocol =
                    (NETunnelProviderProtocol *)candidate.protocolConfiguration;

                if ([protocol isKindOfClass:[NETunnelProviderProtocol class]] &&
                    [protocol.providerBundleIdentifier
                        isEqualToString:DeliriuumProviderBundleIdentifier]) {
                    manager = candidate;
                    break;
                }
            }

            if (manager == nil) {
                manager = [[NETunnelProviderManager alloc] init];
            }

            NETunnelProviderProtocol *protocol =
                [[NETunnelProviderProtocol alloc] init];

            protocol.providerBundleIdentifier =
                DeliriuumProviderBundleIdentifier;

            protocol.serverAddress = @"Deliriuum Direct";

            protocol.providerConfiguration = @{
                @"wireguardConfig": wireguardConfig
            };

            manager.protocolConfiguration = protocol;
            manager.localizedDescription = @"Deliriuum Direct";
            manager.enabled = YES;

            DeliriuumManager = manager;

            [manager saveToPreferencesWithCompletionHandler:^(NSError *saveError) {

                if (saveError != nil) {
                    failure = saveError.localizedDescription;
                    dispatch_semaphore_signal(semaphore);
                    return;
                }

                [manager loadFromPreferencesWithCompletionHandler:^(NSError *loadError) {

                    if (loadError != nil) {
                        failure = loadError.localizedDescription;
                        dispatch_semaphore_signal(semaphore);
                        return;
                    }

                    NSError *startError = nil;

                    BOOL started =
                        [manager.connection startVPNTunnelAndReturnError:&startError];

                    if (!started) {
                        failure = startError.localizedDescription
                            ?: @"Impossible de démarrer le VPN.";
                        dispatch_semaphore_signal(semaphore);
                        return;
                    }

                    result = 0;
                    dispatch_semaphore_signal(semaphore);
                }];
            }];
        }];

        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

        if (result != 0) {
            set_error(
                error_buffer,
                error_buffer_len,
                failure ?: @"Erreur NetworkExtension."
            );
        }

        return result;
    }
}

int deliriuum_vpn_down(void)
{
    @autoreleasepool {
        if (DeliriuumManager != nil) {
            [DeliriuumManager.connection stopVPNTunnel];
        }

        return 0;
    }
}

int deliriuum_vpn_status(void)
{
    @autoreleasepool {
        if (DeliriuumManager == nil) {
            return 0;
        }

        switch (DeliriuumManager.connection.status) {
            case NEVPNStatusConnected:
            case NEVPNStatusConnecting:
            case NEVPNStatusReasserting:
                return 1;

            default:
                return 0;
        }
    }
}

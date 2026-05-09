{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module BraiinsMonitor (main) where

import Control.Applicative ((<|>))
import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, try)
import Control.Monad (forM, forM_, unless, when)
import Data.Aeson
import Data.Aeson.Types (Parser)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString.Char8 qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Char (isAlphaNum, isDigit)
import Data.Foldable (toList)
import Data.List (nub, sortOn)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, mapMaybe)
import Data.Ord (Down (..))
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time
import GHC.Generics (Generic)
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Status (statusCode)
import System.Directory (createDirectoryIfMissing, doesFileExist)
import System.Environment (getArgs, lookupEnv)
import System.Exit (ExitCode (..))
import System.Process (readProcessWithExitCode)
import Text.Printf (printf)
import Text.Read (readMaybe)

configPath, envPath, statePath, dbPath :: FilePath
configPath = "/etc/braiins-monitor/config.json"
envPath = "/etc/braiins-monitor/env"
statePath = "/var/lib/braiins-monitor/state.json"
dbPath = "/var/lib/braiins-monitor/incidents.sqlite"

binaryVersion :: Text
binaryVersion = "2.0.0"

data Severity = Warning | Critical
  deriving (Eq, Ord, Show, Generic)

instance ToJSON Severity where
  toJSON Warning = String "warning"
  toJSON Critical = String "critical"

instance FromJSON Severity where
  parseJSON = withText "Severity" $ \t -> case T.toLower (T.strip t) of
    "warning" -> pure Warning
    "critical" -> pure Critical
    other -> fail ("unknown severity: " <> T.unpack other)

severityText :: Severity -> Text
severityText Warning = "warning"
severityText Critical = "critical"

data IssueCategory
  = CatSystemState
  | CatSystemPort
  | CatSystemHealth
  | CatSystemResult
  | CatSystemStale
  | CatBotService
  | CatBotPort
  | CatBotConfigRead
  | CatBotConfigInvalid
  | CatBotUnknownModel
  | CatResource
  | CatProviderStatus
  | CatProviderPoll
  deriving (Eq, Ord, Show, Generic)

issueCategoryText :: IssueCategory -> Text
issueCategoryText CatSystemState = "system_state"
issueCategoryText CatSystemPort = "system_port"
issueCategoryText CatSystemHealth = "system_health"
issueCategoryText CatSystemResult = "system_result"
issueCategoryText CatSystemStale = "system_stale"
issueCategoryText CatBotService = "bot_service"
issueCategoryText CatBotPort = "bot_port"
issueCategoryText CatBotConfigRead = "bot_config_read"
issueCategoryText CatBotConfigInvalid = "bot_config_invalid"
issueCategoryText CatBotUnknownModel = "bot_unknown_model"
issueCategoryText CatResource = "resource"
issueCategoryText CatProviderStatus = "provider_status"
issueCategoryText CatProviderPoll = "provider_poll"

parseIssueCategory :: Text -> Maybe IssueCategory
parseIssueCategory raw = case T.toLower (T.strip raw) of
  "system_state" -> Just CatSystemState
  "system_port" -> Just CatSystemPort
  "system_health" -> Just CatSystemHealth
  "system_result" -> Just CatSystemResult
  "system_stale" -> Just CatSystemStale
  "bot_service" -> Just CatBotService
  "bot_port" -> Just CatBotPort
  "bot_config_read" -> Just CatBotConfigRead
  "bot_config_invalid" -> Just CatBotConfigInvalid
  "bot_unknown_model" -> Just CatBotUnknownModel
  "resource" -> Just CatResource
  "provider_status" -> Just CatProviderStatus
  "provider_poll" -> Just CatProviderPoll
  _ -> Nothing

instance ToJSON IssueCategory where
  toJSON = String . issueCategoryText

instance FromJSON IssueCategory where
  parseJSON = withText "IssueCategory" $ \t ->
    maybe (fail ("unknown issue category: " <> T.unpack t)) pure (parseIssueCategory t)

data Issue = Issue
  { issueId :: Text
  , severity :: Severity
  , component :: Text
  , summary :: Text
  , detail :: Text
  , category :: IssueCategory
  , maintenanceTarget :: Maybe Text
  } deriving (Eq, Show, Generic)

instance ToJSON Issue where
  toJSON Issue {..} = object
    [ "issue_id" .= issueId
    , "severity" .= severity
    , "component" .= component
    , "summary" .= summary
    , "detail" .= detail
    , "category" .= category
    , "maintenance_target" .= maintenanceTarget
    ]

instance FromJSON Issue where
  parseJSON = withObject "Issue" $ \o ->
    Issue <$> o .: "issue_id"
          <*> o .: "severity"
          <*> o .: "component"
          <*> o .: "summary"
          <*> o .: "detail"
          <*> o .:? "category" .!= CatProviderPoll
          <*> o .:? "maintenance_target"

data PendingEntry = PendingEntry
  { pendingIssue :: Issue
  , pendingCount :: Int
  , pendingFirstSeen :: UTCTime
  , pendingLastSeen :: UTCTime
  } deriving (Eq, Show, Generic)

instance ToJSON PendingEntry where
  toJSON PendingEntry {..} = object
    [ "issue" .= pendingIssue
    , "count" .= pendingCount
    , "first_seen" .= isoZ pendingFirstSeen
    , "last_seen" .= isoZ pendingLastSeen
    ]

instance FromJSON PendingEntry where
  parseJSON = withObject "PendingEntry" $ \o -> do
    pendingIssue <- o .: "issue"
    pendingCount <- o .: "count"
    pendingFirstSeen <- o .: "first_seen" >>= parseIsoField
    pendingLastSeen <- o .: "last_seen" >>= parseIsoField
    pure PendingEntry {..}

newtype StateFile = StateFile { pendingMap :: Map Text PendingEntry }
  deriving (Eq, Show)

instance ToJSON StateFile where
  toJSON (StateFile pending) = object ["pending" .= pending]

instance FromJSON StateFile where
  parseJSON = withObject "StateFile" $ \o -> StateFile <$> o .:? "pending" .!= Map.empty

data ResourceMemory = ResourceMemory { memoryThresholdPct :: Double }
  deriving (Eq, Show)

data ResourceDisk = ResourceDisk
  { diskPath :: FilePath
  , diskLabel :: Text
  , diskThresholdPct :: Double
  } deriving (Eq, Show)

data ResourcesConfig = ResourcesConfig
  { memoryCfg :: ResourceMemory
  , disksCfg :: [ResourceDisk]
  } deriving (Eq, Show)

data ServiceKind = ServiceDaemon | ServiceTimer | ServiceOneshot
  deriving (Eq, Show)

data ServiceConfig = ServiceConfig
  { serviceUnit :: Text
  , serviceLabel :: Text
  , serviceKind :: ServiceKind
  , serviceUser :: Maybe Text
  , servicePort :: Maybe Int
  , serviceHealthUrl :: Maybe Text
  , serviceHealthExpect :: Map Text Value
  , serviceStaleAfterMinutes :: Maybe Int
  } deriving (Eq, Show)

data RequiredPort = RequiredPort
  { requiredPort :: Int
  , requiredLabel :: Text
  } deriving (Eq, Show)

data BotConfig = BotConfig
  { botUser :: Text
  , botLabel :: Text
  , botGatewayPort :: Int
  , botRuntime :: Text
  , botServiceUnitOverride :: Maybe Text
  , botConfigPathOverride :: Maybe FilePath
  , botGmailAccountOverride :: Maybe Text
  , botGmailPortOverride :: Maybe Int
  , botRequiredPorts :: [RequiredPort]
  } deriving (Eq, Show)

data DailyReportConfig = DailyReportConfig
  { reportEnabled :: Bool
  , reportChatId :: Text
  , reportTimeUtc :: Text
  , reportRetentionDays :: Int
  , reportComponentLimit :: Int
  , reportActiveLimit :: Int
  } deriving (Eq, Show)

data AnthropicStatusConfig = AnthropicStatusConfig
  { anthropicEnabled :: Bool
  , anthropicSummaryUrl :: Text
  , anthropicWatchedServices :: [Text]
  } deriving (Eq, Show)

data Config = Config
  { telegramChatId :: Text
  , telegramWarningDmChatId :: Text
  , recentWindowMinutes :: Int
  , resources :: ResourcesConfig
  , systemServices :: [ServiceConfig]
  , bots :: [BotConfig]
  , botStartGraceSeconds :: Int
  , stabilizationRetrySeconds :: Int
  , dailyReport :: DailyReportConfig
  , anthropicStatus :: AnthropicStatusConfig
  , failureConfirmations :: Int
  , plannedRestartWindowSeconds :: Int
  } deriving (Eq, Show)

instance FromJSON ResourceMemory where
  parseJSON = withObject "ResourceMemory" $ \o ->
    ResourceMemory <$> o .:? "threshold_pct" .!= 80

instance FromJSON ResourceDisk where
  parseJSON = withObject "ResourceDisk" $ \o ->
    ResourceDisk <$> o .:? "path" .!= "/"
                 <*> o .:? "label" .!= "root filesystem"
                 <*> o .:? "threshold_pct" .!= 80

instance FromJSON ResourcesConfig where
  parseJSON = withObject "ResourcesConfig" $ \o -> do
    memoryCfg <- o .:? "memory" .!= ResourceMemory 80
    disksCfg <- o .:? "disks" .!= [ResourceDisk "/" "root filesystem" 80]
    pure ResourcesConfig {..}

instance FromJSON ServiceConfig where
  parseJSON = withObject "ServiceConfig" $ \o -> do
    serviceUnit <- o .: "unit"
    serviceLabel <- o .: "label"
    kindTxt <- fmap (T.toLower . T.strip) (o .:? "kind" .!= "daemon")
    let serviceKind = case kindTxt of
          "timer" -> ServiceTimer
          "oneshot" -> ServiceOneshot
          _ -> ServiceDaemon
    serviceUser <- o .:? "user"
    servicePort <- o .:? "port"
    serviceHealthUrl <- o .:? "health_url"
    serviceHealthExpect <- o .:? "health_expect" .!= Map.empty
    serviceStaleAfterMinutes <- o .:? "stale_after_minutes"
    pure ServiceConfig {..}

instance FromJSON RequiredPort where
  parseJSON = withObject "RequiredPort" $ \o ->
    RequiredPort <$> o .: "port" <*> o .: "label"

instance FromJSON BotConfig where
  parseJSON = withObject "BotConfig" $ \o -> do
    botUser <- o .: "user"
    botLabel <- o .: "label"
    botGatewayPort <- o .: "gateway_port"
    botRuntime <- fmap (T.toLower . T.strip) (o .:? "runtime" .!= "openclaw")
    botServiceUnitOverride <- o .:? "service_unit"
    botConfigPathOverride <- o .:? "config_path"
    botGmailAccountOverride <- o .:? "gmail_account"
    botGmailPortOverride <- o .:? "gmail_port"
    botRequiredPorts <- o .:? "required_ports" .!= []
    pure BotConfig {..}

instance FromJSON DailyReportConfig where
  parseJSON = withObject "DailyReportConfig" $ \o -> do
    reportEnabled <- o .:? "enabled" .!= True
    reportChatId <- o .:? "chat_id" .!= ""
    reportTimeUtc <- o .:? "time_utc" .!= "00:00"
    reportRetentionDays <- o .:? "retention_days" .!= 30
    reportComponentLimit <- o .:? "component_limit" .!= 8
    reportActiveLimit <- o .:? "active_limit" .!= 8
    pure DailyReportConfig {..}

instance FromJSON AnthropicStatusConfig where
  parseJSON = withObject "AnthropicStatusConfig" $ \o -> do
    anthropicEnabled <- o .:? "enabled" .!= True
    anthropicSummaryUrl <- o .:? "summary_url" .!= "https://status.claude.com/api/v2/summary.json"
    anthropicWatchedServices <- o .:? "watched_services" .!=
      [ "claude.ai"
      , "platform.claude.com"
      , "console.anthropic.com"
      , "Claude API"
      , "api.anthropic.com"
      , "Claude Code"
      , "Claude for Government"
      ]
    pure AnthropicStatusConfig {..}

instance FromJSON Config where
  parseJSON = withObject "Config" $ \o -> do
    telegramChatId <- o .:? "telegram_chat_id" .!= ""
    telegramWarningDmChatId <- o .:? "telegram_warning_dm_chat_id" .!= telegramChatId
    recentWindowMinutes <- o .:? "recent_window_minutes" .!= 15
    resources <- o .:? "resources" .!= ResourcesConfig (ResourceMemory 80) [ResourceDisk "/" "root filesystem" 80]
    systemServices <- o .:? "system_services" .!= []
    bots <- o .:? "bots" .!= []
    botStartGraceSeconds <- o .:? "bot_start_grace_seconds" .!= 180
    stabilizationRetrySeconds <- o .:? "stabilization_retry_seconds" .!= 20
    dailyReport <- o .:? "daily_report" .!= DailyReportConfig True telegramWarningDmChatId "00:00" 30 8 8
    anthropicStatus <- o .:? "anthropic_status" .!= AnthropicStatusConfig True "https://status.claude.com/api/v2/summary.json" []
    failureConfirmations <- o .:? "failure_confirmations" .!= 2
    plannedRestartWindowSeconds <- o .:? "planned_restart_window_seconds" .!= 900
    pure Config {..}

data OpenIncident = OpenIncident
  { oiIssueId :: Text
  , oiSeverity :: Severity
  , oiComponent :: Text
  , oiSummary :: Text
  , oiDetail :: Text
  , oiFirstSeen :: UTCTime
  , oiLastSeen :: UTCTime
  , oiResolvedAt :: Maybe UTCTime
  } deriving (Eq, Show)

instance FromJSON OpenIncident where
  parseJSON = withObject "OpenIncident" $ \o -> do
    oiIssueId <- o .: "issue_id"
    oiSeverity <- o .: "severity"
    oiComponent <- o .: "component"
    oiSummary <- o .: "summary"
    oiDetail <- o .: "detail"
    oiFirstSeen <- o .: "first_seen" >>= parseIsoField
    oiLastSeen <- o .: "last_seen" >>= parseIsoField
    oiResolvedAt <- (o .:? "resolved_at") >>= traverse parseIsoField
    pure OpenIncident {..}

instance ToJSON OpenIncident where
  toJSON OpenIncident {..} = object
    [ "issue_id" .= oiIssueId
    , "severity" .= oiSeverity
    , "component" .= oiComponent
    , "summary" .= oiSummary
    , "detail" .= oiDetail
    , "first_seen" .= isoZ oiFirstSeen
    , "last_seen" .= isoZ oiLastSeen
    , "resolved_at" .= fmap isoZ oiResolvedAt
    ]

data MaintenanceWindow = MaintenanceWindow
  { mwScope :: Text
  , mwTarget :: Text
  , mwReason :: Text
  , mwStartsAt :: UTCTime
  , mwEndsAt :: UTCTime
  } deriving (Eq, Show)

instance FromJSON MaintenanceWindow where
  parseJSON = withObject "MaintenanceWindow" $ \o -> do
    mwScope <- o .: "scope"
    mwTarget <- o .: "target"
    mwReason <- o .: "reason"
    mwStartsAt <- o .: "starts_at" >>= parseIsoField
    mwEndsAt <- o .: "ends_at" >>= parseIsoField
    pure MaintenanceWindow {..}

data SummaryRow = SummaryRow
  { srSeverity :: Severity
  , srComponent :: Text
  , srSummary :: Text
  , srFirstSeen :: UTCTime
  , srResolvedAt :: Maybe UTCTime
  } deriving (Eq, Show)

instance FromJSON SummaryRow where
  parseJSON = withObject "SummaryRow" $ \o -> do
    srSeverity <- o .: "severity"
    srComponent <- o .: "component"
    srSummary <- o .: "summary"
    srFirstSeen <- o .: "first_seen" >>= parseIsoField
    srResolvedAt <- (o .:? "resolved_at") >>= traverse parseIsoField
    pure SummaryRow {..}

data CountRow = CountRow { countValue :: Int }
  deriving (Eq, Show)

instance FromJSON CountRow where
  parseJSON = withObject "CountRow" $ \o ->
    CountRow <$> o .: "count"

main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> runMonitor
    ["run"] -> runMonitor
    ["debug", "issues"] -> debugIssues
    ["maintenance", "start", scope, target, reason] -> do
      cfg <- readConfigFile
      startMaintenance cfg (T.pack scope) (T.pack target) (T.pack reason) Nothing
    ["maintenance", "start", scope, target, reason, secondsArg] -> do
      cfg <- readConfigFile
      startMaintenance cfg (T.pack scope) (T.pack target) (T.pack reason) (readMaybe secondsArg)
    _ -> error "usage: braiins-monitor [run | debug issues | maintenance start <scope> <target> <reason> [seconds]]"

runMonitor :: IO ()
runMonitor = do
  createDirectoryIfMissing True "/var/lib/braiins-monitor"
  cfg <- readConfigFile
  token <- readBotToken
  ensureDbSchema
  now <- getCurrentTime
  pruneMaintenance now
  initialIssues <- collectIssues cfg now
  finalIssues <-
    if any isTransientOutage initialIssues && stabilizationRetrySeconds cfg > 0
      then do
        threadDelay (stabilizationRetrySeconds cfg * 1000000)
        collectIssues cfg =<< getCurrentTime
      else pure initialIssues
  maint <- activeMaintenance now
  let visibleIssues = filter (not . isSuppressedByMaintenance maint) finalIssues
  state0 <- readStateFile
  openRows <- getOpenIncidents
  let openMap = Map.fromList [(oiIssueId row, row) | row <- openRows]
  let currentMap = Map.fromList [(issueId issue, issue) | issue <- visibleIssues]
  let (pending1, newlyOpened) = reconcilePending now (failureConfirmations cfg) state0 openMap currentMap
  let ongoing = Map.elems (Map.intersection openMap currentMap)
  let resolvedRows = [row | (iid, row) <- Map.toList openMap, Map.notMember iid currentMap]
  forM_ ongoing $ \row -> touchOpenIncident (oiIssueId row) now
  forM_ newlyOpened $ \issue -> insertIncident issue now
  forM_ resolvedRows $ \row -> resolveIncident (oiIssueId row) now
  let pending2 = Map.filterWithKey (\iid _ -> Map.member iid currentMap && Map.notMember iid openMap) pending1
  openRowsAfter <- getOpenIncidents
  writeStateSnapshot now pending2 openRowsAfter maint
  let openedForDm = sortIssues newlyOpened
  let resolvedForDm = sortOn oiIssueId resolvedRows
  when (not (null openedForDm)) $ sendIssueMessage token (telegramWarningDmChatId cfg) "Monitor alerts" openedForDm
  when (not (null resolvedForDm)) $ sendResolvedMessage token (telegramWarningDmChatId cfg) "Monitor resolved" resolvedForDm
  let openedForGroup = filter isGroupWorthy openedForDm
  let resolvedForGroup = filter (isGroupWorthy . incidentToIssue) resolvedForDm
  when (not (null openedForGroup)) $ sendIssueMessage token (telegramChatId cfg) "Monitor critical alerts" openedForGroup
  when (not (null resolvedForGroup)) $ sendResolvedMessage token (telegramChatId cfg) "Monitor critical resolved" resolvedForGroup
  maybeSendDailyReport cfg token now

debugIssues :: IO ()
debugIssues = do
  createDirectoryIfMissing True "/var/lib/braiins-monitor"
  ensureDbSchema
  cfg <- readConfigFile
  now <- getCurrentTime
  issues <- collectIssues cfg now
  maint <- activeMaintenance now
  let visible = filter (not . isSuppressedByMaintenance maint) issues
  LBS.putStr (encode (object ["generated_at" .= isoZ now, "issues" .= visible, "suppressed" .= filter (isSuppressedByMaintenance maint) issues]))

readConfigFile :: IO Config
readConfigFile = do
  bytes <- LBS.readFile configPath
  case eitherDecode bytes of
    Left err -> error ("failed to parse config: " <> err)
    Right cfg -> pure cfg

readBotToken :: IO Text
readBotToken = do
  inline <- lookupEnv "BRAIINS_MONITOR_BOT_TOKEN"
  case fmap T.pack inline of
    Just token | not (T.null (T.strip token)) -> pure token
    _ -> do
      exists <- doesFileExist envPath
      unless exists (error "missing BRAIINS_MONITOR_BOT_TOKEN and /etc/braiins-monitor/env")
      body <- readFile envPath
      case [T.pack (drop 1 rhs) | line <- lines body, let (lhs, rhs) = break (== '=') line, lhs == "BRAIINS_MONITOR_BOT_TOKEN"] of
        token : _ -> pure token
        [] -> error "BRAIINS_MONITOR_BOT_TOKEN not found in env file"

collectIssues :: Config -> UTCTime -> IO [Issue]
collectIssues cfg now = do
  ports <- listeningPorts
  sysIssues <- checkSystemServices cfg ports now
  botIssues <- checkBots cfg ports now
  resourceIssues <- checkResources cfg
  providerIssues <- checkAnthropicStatus cfg
  pure (sysIssues <> botIssues <> resourceIssues <> providerIssues)

checkSystemServices :: Config -> [Int] -> UTCTime -> IO [Issue]
checkSystemServices cfg ports now = fmap concat $ forM (systemServices cfg) $ \svc -> do
  props <- systemdShowService (serviceUser svc) (serviceUnit svc)
  let active = Map.findWithDefault "unknown" "ActiveState" props
  let sub = Map.findWithDefault "unknown" "SubState" props
  let result = Map.findWithDefault "unknown" "Result" props
  let exitTs = Map.lookup "ExecMainExitTimestamp" props >>= parseSystemdTimestamp
  case serviceKind svc of
    ServiceTimer -> pure
      [ Issue
          ("system:" <> serviceUnit svc <> ":state")
          Critical
          (serviceLabel svc)
          (serviceLabel svc <> " is not waiting")
          ("state=" <> active <> "/" <> sub)
          CatSystemState
          Nothing
      | active /= "active" || not (sub `elem` ["waiting", "running", "elapsed"]) ]
    ServiceOneshot -> pure $ resultIssues <> staleIssues
      where
        resultIssues =
          [ Issue
              ("system:" <> serviceUnit svc <> ":result")
              Critical
              (serviceLabel svc)
              (serviceLabel svc <> " last run failed")
              ("result=" <> result)
              CatSystemResult
              Nothing
          | result /= "success" && result /= "" && result /= "done"
          ]
        staleIssues = case (serviceStaleAfterMinutes svc, exitTs) of
          (Just minutes, Just ts) | diffUTCTime now ts > fromIntegral (minutes * 60) ->
            [ Issue
                ("system:" <> serviceUnit svc <> ":stale")
                Warning
                (serviceLabel svc)
                (serviceLabel svc <> " looks stale")
                ("last successful run at " <> isoZ ts)
                CatSystemStale
                Nothing
            ]
          _ -> []
    ServiceDaemon -> do
      let stateIssues =
            [ Issue
                ("system:" <> serviceUnit svc <> ":state")
                Critical
                (serviceLabel svc)
                (serviceLabel svc <> " is not running")
                ("state=" <> active <> "/" <> sub)
                CatSystemState
                Nothing
            | active /= "active" || sub /= "running"
            ]
      let portIssues = case servicePort svc of
            Just port | port `notElem` ports ->
              [ Issue
                  ("system:" <> serviceUnit svc <> ":port:" <> T.pack (show port))
                  Critical
                  (serviceLabel svc)
                  (serviceLabel svc <> " is not listening on " <> T.pack (show port))
                  ("expected listener on " <> T.pack (show port))
                  CatSystemPort
                  Nothing
              ]
            _ -> []
      healthIssues <- case serviceHealthUrl svc of
        Nothing -> pure []
        Just url -> do
          resultE <- try (httpGetJson url) :: IO (Either SomeException Value)
          pure $ case resultE of
            Left exc ->
              [ Issue
                  ("system:" <> serviceUnit svc <> ":health")
                  Critical
                  (serviceLabel svc)
                  (serviceLabel svc <> " health check failed")
                  (T.pack (show exc))
                  CatSystemHealth
                  Nothing
              ]
            Right (Object actual) ->
              let mismatches =
                    [ key <> " expected " <> renderJsonValue expected <> " got " <> maybe "null" renderJsonValue (KeyMap.lookup (Key.fromText key) actual)
                    | (key, expected) <- Map.toList (serviceHealthExpect svc)
                    , KeyMap.lookup (Key.fromText key) actual /= Just expected
                    ]
              in if null mismatches
                   then []
                   else [ Issue
                            ("system:" <> serviceUnit svc <> ":health")
                            Critical
                            (serviceLabel svc)
                            (serviceLabel svc <> " health check failed")
                            (T.intercalate "; " mismatches)
                            CatSystemHealth
                            Nothing
                        ]
            Right _ ->
              [ Issue
                  ("system:" <> serviceUnit svc <> ":health")
                  Critical
                  (serviceLabel svc)
                  (serviceLabel svc <> " health check returned invalid JSON")
                  "expected a JSON object"
                  CatSystemHealth
                  Nothing
              ]
      pure (stateIssues <> portIssues <> healthIssues)

checkBots :: Config -> [Int] -> UTCTime -> IO [Issue]
checkBots cfg ports now = fmap concat $ forM (bots cfg) $ \bot -> do
  props <- systemdShowService (Just (botUser bot)) (botServiceUnit bot)
  let active = Map.findWithDefault "unknown" "ActiveState" props
  let sub = Map.findWithDefault "unknown" "SubState" props
  let startTime = Map.lookup "ExecMainStartTimestamp" props >>= parseSystemdTimestamp
  let inStartGrace = case startTime of
        Just ts -> diffUTCTime now ts < fromIntegral (botStartGraceSeconds cfg)
        Nothing -> False
  let mk iid sev msg det cat = Issue iid sev (botLabel bot) msg det cat (Just (botUser bot))
  let serviceIssues =
        [ mk ("bot:" <> botUser bot <> ":service") Critical (botLabel bot <> " gateway is not running") ("unit=" <> botServiceUnit bot <> " state=" <> active <> "/" <> sub) CatBotService
        | active /= "active" || sub /= "running"
        ]
  configValueE <- readBotConfigValue bot
  case configValueE of
    Left err -> pure (serviceIssues <> [mk ("bot:" <> botUser bot <> ":config_read") Critical (botLabel bot <> " config could not be read") err CatBotConfigRead])
    Right configValue -> do
      let (gmailAccount, gmailPort) = extractBotGmailWatch bot configValue
      let portIssues =
            if inStartGrace || not (null serviceIssues)
              then []
              else
                [ mk ("bot:" <> botUser bot <> ":gateway_port") Critical (botLabel bot <> " gateway port is down") ("expected listener on " <> T.pack (show (botGatewayPort bot))) CatBotPort
                | botGatewayPort bot `notElem` ports
                ]
                <> [ mk ("bot:" <> botUser bot <> ":required_port:" <> T.pack (show (requiredPort rp))) Critical (botLabel bot <> " " <> requiredLabel rp <> " is down") ("expected listener on " <> T.pack (show (requiredPort rp))) CatBotPort
                   | rp <- botRequiredPorts bot, requiredPort rp `notElem` ports
                   ]
                <> [ mk ("bot:" <> botUser bot <> ":gmail_port") Critical (botLabel bot <> " Gmail watcher is not listening") ("expected listener on " <> T.pack (show gp) <> " for " <> ga) CatBotPort
                   | Just ga <- [gmailAccount], Just gp <- [gmailPort], gp `notElem` ports
                   ]
      logIssues <- case startTime of
        Nothing -> pure []
        Just startedAt -> do
          logs <- journalSince bot startedAt
          let unknowns = uniqueUnknownModels logs
          let unknownIssues =
                [ mk ("bot:" <> botUser bot <> ":unknown_model") Critical (botLabel bot <> " hit an unknown model error") (T.intercalate ", " unknowns) CatBotUnknownModel
                | not (null unknowns)
                ]
          let configInvalidIssues =
                [ mk ("bot:" <> botUser bot <> ":config_invalid") Critical (botLabel bot <> " started with an unreadable or invalid config") "matched config invalid / EACCES after current service start" CatBotConfigInvalid
                | containsAny logs ["Failed to read config", "Config invalid", "EACCES: permission denied"]
                ]
          pure (unknownIssues <> configInvalidIssues)
      pure (serviceIssues <> portIssues <> logIssues)

checkResources :: Config -> IO [Issue]
checkResources cfg = do
  memIssues <- checkMemory (memoryCfg (resources cfg))
  diskIssues <- fmap concat (mapM checkDisk (disksCfg (resources cfg)))
  pure (memIssues <> diskIssues)

checkMemory :: ResourceMemory -> IO [Issue]
checkMemory ResourceMemory {..} = do
  body <- readFile "/proc/meminfo"
  let kv = Map.fromList (mapMaybe parseMemLine (lines body))
  case (Map.lookup "MemTotal" kv, Map.lookup "MemAvailable" kv <|> Map.lookup "MemFree" kv) of
    (Just totalKb, Just availKb) -> do
      let total = fromIntegral totalKb :: Double
      let used = fromIntegral (totalKb - availKb) :: Double
      let pct = if total <= 0 then 0 else (used / total) * 100
      pure
        [ Issue "resource:memory:high" Warning "system memory" "system memory usage is high" (T.pack (printf "%.1f%% used" pct)) CatResource Nothing
        | pct >= memoryThresholdPct
        ]
    _ -> pure [Issue "resource:memory:read_error" Warning "system memory" "system memory usage could not be checked" "failed to parse /proc/meminfo" CatResource Nothing]

checkDisk :: ResourceDisk -> IO [Issue]
checkDisk ResourceDisk {..} = do
  (code, out, err) <- readProcessWithExitCode "df" ["-B1", "--output=size,used", diskPath] ""
  case code of
    ExitFailure _ -> pure [Issue ("resource:disk:" <> T.pack diskPath <> ":read_error") Warning diskLabel (diskLabel <> " usage could not be checked") (T.pack err) CatResource Nothing]
    ExitSuccess -> case parseDfOutput out of
      Just (total, used) -> do
        let pct = if total <= 0 then 0 else (used / total) * 100
        pure
          [ Issue ("resource:disk:" <> T.pack diskPath <> ":high") Warning diskLabel (diskLabel <> " usage is high") (T.pack (printf "%.1f%% used" pct)) CatResource Nothing
          | pct >= diskThresholdPct
          ]
      Nothing -> pure [Issue ("resource:disk:" <> T.pack diskPath <> ":read_error") Warning diskLabel (diskLabel <> " usage could not be checked") "failed to parse df output" CatResource Nothing]

checkAnthropicStatus :: Config -> IO [Issue]
checkAnthropicStatus cfg
  | not (anthropicEnabled (anthropicStatus cfg)) = pure []
  | otherwise = do
      resultE <- try (httpGetJson (anthropicSummaryUrl (anthropicStatus cfg))) :: IO (Either SomeException Value)
      case resultE of
        Left exc -> pure [Issue "provider:anthropic:status:poll_failed" Warning "Anthropic status" "Anthropic status poll failed" (T.pack (show exc)) CatProviderPoll Nothing]
        Right payload -> pure (anthropicIssuesFromJson (anthropicStatus cfg) payload)

anthropicIssuesFromJson :: AnthropicStatusConfig -> Value -> [Issue]
anthropicIssuesFromJson AnthropicStatusConfig {..} value =
  case value of
    Object root ->
      let watchedTerms = map (T.toLower . T.strip) anthropicWatchedServices
          watched name = let lower = T.toLower name in any (`T.isInfixOf` lower) watchedTerms
          overallIssues = case KeyMap.lookup "status" root of
            Just (Object statusObj) ->
              let description = lookupText "description" statusObj
                  indicator = lookupText "indicator" statusObj
              in case anthropicSeverity indicator <|> anthropicSeverity description of
                   Just sev -> [Issue "provider:anthropic:status:overall" sev "Anthropic status" ("Claude overall status is " <> if T.null description then "unknown" else description) ("indicator=" <> indicator) CatProviderStatus Nothing]
                   Nothing -> []
            _ -> []
          componentIssues = case KeyMap.lookup "components" root of
            Just (Array xs) -> concatMap (componentIssue watched) (toList xs)
            _ -> []
          incidentIssues = case KeyMap.lookup "incidents" root of
            Just (Array xs) -> concatMap (incidentIssue watched) (toList xs)
            _ -> []
      in overallIssues <> componentIssues <> incidentIssues
    _ -> [Issue "provider:anthropic:status:poll_failed" Warning "Anthropic status" "Anthropic status poll failed" "expected JSON object" CatProviderPoll Nothing]
  where
    componentIssue watched (Object o) =
      let name = lookupText "name" o
          statusTxt = lookupText "status" o
      in case anthropicSeverity statusTxt of
           Just sev | watched name -> [Issue ("provider:anthropic:component:" <> slugify name) sev name ("Anthropic component status is " <> statusTxt) ("reported by " <> anthropicSummaryUrl) CatProviderStatus Nothing]
           _ -> []
    componentIssue _ _ = []
    incidentIssue watched (Object o) =
      let incidentId = lookupText "id" o
          name = lookupText "name" o
          statusTxt = lookupText "status" o
          impact = lookupText "impact" o
          componentNames = case KeyMap.lookup "components" o of
            Just (Array xs) -> [lookupText "name" comp | Object comp <- toList xs]
            _ -> []
          related = filter watched componentNames
      in case anthropicSeverity impact <|> anthropicSeverity statusTxt of
           Just sev | not (null related) -> [Issue ("provider:anthropic:incident:" <> if T.null incidentId then "unknown" else incidentId) sev "Anthropic incident" (name <> " [" <> statusTxt <> "]") ("impact=" <> impact <> "; components=" <> T.intercalate ", " related) CatProviderStatus Nothing]
           _ -> []
    incidentIssue _ _ = []

anthropicSeverity :: Text -> Maybe Severity
anthropicSeverity raw =
  case T.toLower (T.replace " " "_" (T.strip raw)) of
    "" -> Nothing
    "operational" -> Nothing
    "all_systems_operational" -> Nothing
    "resolved" -> Nothing
    "none" -> Nothing
    "degraded_performance" -> Just Warning
    "minor" -> Just Warning
    "partial_outage" -> Just Warning
    "under_maintenance" -> Just Warning
    "maintenance" -> Just Warning
    "investigating" -> Just Warning
    "identified" -> Just Warning
    "monitoring" -> Just Warning
    "major_outage" -> Just Critical
    "major" -> Just Critical
    "critical" -> Just Critical
    _ -> Just Warning

systemdShowService :: Maybe Text -> Text -> IO (Map Text Text)
systemdShowService maybeUser unitName = do
  let args = case maybeUser of
        Nothing -> ["systemctl", "show", T.unpack unitName]
        Just user -> ["systemctl", "--user", "-M", T.unpack user <> "@", "show", T.unpack unitName]
  (code, out, err) <- runCommandCapture args
  pure $ case code of
    ExitSuccess -> parseKeyValueLines out
    ExitFailure _ -> Map.fromList [("ActiveState", "unknown"), ("SubState", T.pack (trim err))]

journalSince :: BotConfig -> UTCTime -> IO Text
journalSince bot sinceTime = do
  uid <- readUid (botUser bot)
  let user = T.unpack (botUser bot)
  let unitName = T.unpack (botServiceUnit bot)
  let args =
        [ "runuser", "-u", user, "--", "env"
        , "XDG_RUNTIME_DIR=/run/user/" <> show uid
        , "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" <> show uid <> "/bus"
        , "journalctl", "--user", "-u", unitName
        , "--since", systemdSince sinceTime
        , "-o", "cat", "--no-pager"
        ]
  (code, out, err) <- runCommandCapture args
  pure $ T.pack $ case code of
    ExitSuccess -> out
    ExitFailure _ -> err

readUid :: Text -> IO Int
readUid user = do
  (code, out, err) <- readProcessWithExitCode "id" ["-u", T.unpack user] ""
  case code of
    ExitSuccess -> case readMaybe (trim out) of
      Just uid -> pure uid
      Nothing -> error ("failed to parse uid for " <> T.unpack user)
    ExitFailure _ -> error ("failed to resolve uid for " <> T.unpack user <> ": " <> err)

botServiceUnit :: BotConfig -> Text
botServiceUnit BotConfig {..} = fromMaybe defaultUnit botServiceUnitOverride
  where
    defaultUnit = if botRuntime == "nullclaw" then "nullclaw-gateway.service" else "openclaw-gateway.service"

botConfigPath :: BotConfig -> FilePath
botConfigPath BotConfig {..} = fromMaybe fallbackPath botConfigPathOverride
  where
    fallbackPath = if botRuntime == "nullclaw"
      then "/home/" <> T.unpack botUser <> "/.nullclaw/config.json"
      else "/home/" <> T.unpack botUser <> "/.openclaw/openclaw.json"

readBotConfigValue :: BotConfig -> IO (Either Text Value)
readBotConfigValue bot = do
  resultE <- try (LBS.readFile (botConfigPath bot)) :: IO (Either SomeException LBS.ByteString)
  pure $ case resultE of
    Left exc -> Left (T.pack (show exc))
    Right bytes -> case eitherDecode bytes of
      Left err -> Left (T.pack err)
      Right value -> Right value

extractBotGmailWatch :: BotConfig -> Value -> (Maybe Text, Maybe Int)
extractBotGmailWatch BotConfig {..} value =
  let nested path = lookupPath path value
      account = botGmailAccountOverride <|> (nested ["hooks", "gmail", "account"] >>= valueText)
      portVal = botGmailPortOverride <|> (nested ["hooks", "gmail", "serve", "port"] >>= valueInt)
  in (account, portVal)

lookupPath :: [Text] -> Value -> Maybe Value
lookupPath [] v = Just v
lookupPath (k : ks) (Object o) = KeyMap.lookup (Key.fromText k) o >>= lookupPath ks
lookupPath _ _ = Nothing

valueText :: Value -> Maybe Text
valueText (String t) = Just t
valueText (Number n) = Just (T.pack (show n))
valueText _ = Nothing

valueInt :: Value -> Maybe Int
valueInt (String t) = readMaybe (T.unpack t)
valueInt (Number n) = readMaybe (show n)
valueInt _ = Nothing

listeningPorts :: IO [Int]
listeningPorts = do
  (code, out, _) <- readProcessWithExitCode "ss" ["-ltnH"] ""
  pure $ case code of
    ExitSuccess -> mapMaybe parsePort (lines out)
    ExitFailure _ -> []

parsePort :: String -> Maybe Int
parsePort line =
  let fields = words line
      localAddr = if length fields >= 4 then fields !! 3 else ""
      digitsRev = takeWhile isDigit (reverse localAddr)
  in if null digitsRev then Nothing else readMaybe (reverse digitsRev)

parseMemLine :: String -> Maybe (String, Int)
parseMemLine line =
  case words line of
    [rawKey, valueKb, _] -> do
      num <- readMaybe valueKb
      pure (filter (/= ':') rawKey, num)
    _ -> Nothing

parseDfOutput :: String -> Maybe (Double, Double)
parseDfOutput out =
  case drop 1 (lines out) of
    row : _ -> case words row of
      [sizeStr, usedStr] -> do
        sizeVal <- readMaybe sizeStr
        usedVal <- readMaybe usedStr
        pure (sizeVal, usedVal)
      _ -> Nothing
    [] -> Nothing

parseKeyValueLines :: String -> Map Text Text
parseKeyValueLines = Map.fromList . mapMaybe parseLine . lines
  where
    parseLine line = case break (== '=') line of
      (key, '=' : value) -> Just (T.pack key, T.pack value)
      _ -> Nothing

parseSystemdTimestamp :: Text -> Maybe UTCTime
parseSystemdTimestamp txt
  | T.null (T.strip txt) = Nothing
  | otherwise = parseTimeM True defaultTimeLocale "%a %Y-%m-%d %H:%M:%S %Z" (T.unpack txt)

systemdSince :: UTCTime -> String
systemdSince = formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S UTC"

isoZ :: UTCTime -> Text
isoZ = T.pack . formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ"

parseIsoField :: Text -> Parser UTCTime
parseIsoField txt =
  case parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%SZ" (T.unpack txt) of
    Just ts -> pure ts
    Nothing -> fail ("invalid timestamp: " <> T.unpack txt)

sqlQuote :: Text -> Text
sqlQuote txt = "'" <> T.replace "'" "''" txt <> "'"

ensureDbSchema :: IO ()
ensureDbSchema = sqliteExec
  [ "CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, issue_id TEXT NOT NULL, severity TEXT NOT NULL, component TEXT NOT NULL, summary TEXT NOT NULL, detail TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT)"
  , "CREATE INDEX IF NOT EXISTS idx_incidents_issue_open ON incidents(issue_id, resolved_at)"
  , "CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen)"
  , "CREATE INDEX IF NOT EXISTS idx_incidents_resolved_at ON incidents(resolved_at)"
  , "CREATE TABLE IF NOT EXISTS daily_reports (report_date TEXT PRIMARY KEY, sent_at TEXT NOT NULL, chat_id TEXT NOT NULL)"
  , "CREATE TABLE IF NOT EXISTS maintenance_windows (id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, created_at TEXT NOT NULL, released_at TEXT)"
  , "CREATE INDEX IF NOT EXISTS idx_maintenance_active ON maintenance_windows(scope, target, released_at, ends_at)"
  ]

sqliteExec :: [Text] -> IO ()
sqliteExec statements = do
  let sql = T.unpack (T.intercalate ";\n" statements <> ";\n")
  (code, _, err) <- readProcessWithExitCode "sqlite3" [dbPath] sql
  case code of
    ExitSuccess -> pure ()
    ExitFailure _ -> error ("sqlite exec failed: " <> err)

sqliteQuery :: FromJSON a => Text -> IO a
sqliteQuery sql = do
  (code, out, err) <- readProcessWithExitCode "sqlite3" ["-json", dbPath, T.unpack sql] ""
  case code of
    ExitFailure _ -> error ("sqlite query failed: " <> err)
    ExitSuccess ->
      let payload = if null (trim out) then "[]" else out
       in case eitherDecode (LBS.fromStrict (BS.pack payload)) of
            Left decodeErr -> error ("sqlite decode failed: " <> decodeErr <> "\nSQL: " <> T.unpack sql <> "\nOUT: " <> out)
            Right value -> pure value

getOpenIncidents :: IO [OpenIncident]
getOpenIncidents = sqliteQuery "SELECT issue_id, severity, component, summary, detail, first_seen, last_seen, resolved_at FROM incidents WHERE resolved_at IS NULL"

insertIncident :: Issue -> UTCTime -> IO ()
insertIncident Issue {..} now = sqliteExec
  [ "INSERT INTO incidents(issue_id, severity, component, summary, detail, first_seen, last_seen, resolved_at) VALUES ("
      <> T.intercalate ","
           [ sqlQuote issueId
           , sqlQuote (severityText severity)
           , sqlQuote component
           , sqlQuote summary
           , sqlQuote detail
           , sqlQuote (isoZ now)
           , sqlQuote (isoZ now)
           , "NULL"
           ]
      <> ")"
  ]

touchOpenIncident :: Text -> UTCTime -> IO ()
touchOpenIncident iid now = sqliteExec
  [ "UPDATE incidents SET last_seen = " <> sqlQuote (isoZ now) <> " WHERE issue_id = " <> sqlQuote iid <> " AND resolved_at IS NULL" ]

resolveIncident :: Text -> UTCTime -> IO ()
resolveIncident iid now = sqliteExec
  [ "UPDATE incidents SET last_seen = " <> sqlQuote (isoZ now) <> ", resolved_at = " <> sqlQuote (isoZ now) <> " WHERE issue_id = " <> sqlQuote iid <> " AND resolved_at IS NULL" ]

readStateFile :: IO StateFile
readStateFile = do
  exists <- doesFileExist statePath
  if not exists
    then pure (StateFile Map.empty)
    else do
      bytes <- LBS.readFile statePath
      case eitherDecode bytes of
        Left _ -> pure (StateFile Map.empty)
        Right value -> pure value

writeStateSnapshot :: UTCTime -> Map Text PendingEntry -> [OpenIncident] -> [MaintenanceWindow] -> IO ()
writeStateSnapshot now pending activeRows maintenance = do
  let payload = object
        [ "last_run_at" .= isoZ now
        , "version" .= binaryVersion
        , "pending" .= pending
        , "active" .= activeRows
        , "maintenance" .= map maintenanceToJson maintenance
        ]
  LBS.writeFile statePath (encode payload)

maintenanceToJson :: MaintenanceWindow -> Value
maintenanceToJson MaintenanceWindow {..} = object
  [ "scope" .= mwScope
  , "target" .= mwTarget
  , "reason" .= mwReason
  , "starts_at" .= isoZ mwStartsAt
  , "ends_at" .= isoZ mwEndsAt
  ]

startMaintenance :: Config -> Text -> Text -> Text -> Maybe Int -> IO ()
startMaintenance cfg scope target reason maybeSeconds = do
  ensureDbSchema
  now <- getCurrentTime
  let duration = fromMaybe (plannedRestartWindowSeconds cfg) maybeSeconds
  let endsAt = addUTCTime (fromIntegral duration) now
  sqliteExec
    [ "INSERT INTO maintenance_windows(scope, target, reason, starts_at, ends_at, created_at, released_at) VALUES ("
        <> T.intercalate ","
             [ sqlQuote scope
             , sqlQuote target
             , sqlQuote reason
             , sqlQuote (isoZ now)
             , sqlQuote (isoZ endsAt)
             , sqlQuote (isoZ now)
             , "NULL"
             ]
        <> ")"
    ]

activeMaintenance :: UTCTime -> IO [MaintenanceWindow]
activeMaintenance now = sqliteQuery $
  "SELECT scope, target, reason, starts_at, ends_at FROM maintenance_windows WHERE released_at IS NULL AND starts_at <= "
  <> sqlQuote (isoZ now)
  <> " AND ends_at > "
  <> sqlQuote (isoZ now)

pruneMaintenance :: UTCTime -> IO ()
pruneMaintenance now =
  sqliteExec ["DELETE FROM maintenance_windows WHERE ends_at < " <> sqlQuote (isoZ (addUTCTime (negate (30 * 86400)) now))]

isSuppressedByMaintenance :: [MaintenanceWindow] -> Issue -> Bool
isSuppressedByMaintenance windows Issue {..} =
  case maintenanceTarget of
    Nothing -> False
    Just target ->
      category `elem` [CatBotService, CatBotPort]
        && any (\mw -> mwScope mw == "bot" && mwTarget mw == target) windows

isTransientOutage :: Issue -> Bool
isTransientOutage Issue {..} = category `elem`
  [CatSystemState, CatSystemPort, CatSystemHealth, CatBotService, CatBotPort]

reconcilePending :: UTCTime -> Int -> StateFile -> Map Text OpenIncident -> Map Text Issue -> (Map Text PendingEntry, [Issue])
reconcilePending now confirmations (StateFile pending0) openMap currentMap =
  foldl step (Map.empty, []) (Map.elems currentMap)
  where
    step (pendingAcc, openedAcc) issue
      | Map.member (issueId issue) openMap = (pendingAcc, openedAcc)
      | otherwise =
          let prior = Map.lookup (issueId issue) pending0
              newCount = maybe 1 ((+ 1) . pendingCount) prior
              firstSeen = maybe now pendingFirstSeen prior
              entry = PendingEntry issue newCount firstSeen now
           in if newCount >= confirmations
                then (pendingAcc, issue : openedAcc)
                else (Map.insert (issueId issue) entry pendingAcc, openedAcc)

maybeSendDailyReport :: Config -> Text -> UTCTime -> IO ()
maybeSendDailyReport cfg token now = do
  let reportCfg = dailyReport cfg
  when (reportEnabled reportCfg) $ do
    let (hh, mm) = parseReportTime (reportTimeUtc reportCfg)
    let today = utctDay now
    let scheduled = UTCTime today (secondsToDiffTime (fromIntegral (hh * 3600 + mm * 60)))
    let summaryDay = addDays (-1) today
    sent <- wasDailyReportSent summaryDay
    when (not sent && now >= scheduled) $ do
      msg <- buildDailyReport reportCfg summaryDay
      sendTelegramText token (reportChatId reportCfg) msg
      markDailyReportSent summaryDay now (reportChatId reportCfg)
      purgeOldDailyReports reportCfg now

wasDailyReportSent :: Day -> IO Bool
wasDailyReportSent day = do
  rows <- (sqliteQuery ("SELECT COUNT(*) AS count FROM daily_reports WHERE report_date = " <> sqlQuote (T.pack (show day))) :: IO [CountRow])
  pure $ case rows of
    CountRow n : _ -> n > 0
    _ -> False

markDailyReportSent :: Day -> UTCTime -> Text -> IO ()
markDailyReportSent day now chatId = sqliteExec
  [ "INSERT OR REPLACE INTO daily_reports(report_date, sent_at, chat_id) VALUES ("
      <> T.intercalate "," [sqlQuote (T.pack (show day)), sqlQuote (isoZ now), sqlQuote chatId]
      <> ")"
  ]

purgeOldDailyReports :: DailyReportConfig -> UTCTime -> IO ()
purgeOldDailyReports DailyReportConfig {..} now = do
  let cutoff = addDays (negate (fromIntegral reportRetentionDays)) (utctDay now)
  sqliteExec ["DELETE FROM daily_reports WHERE report_date < " <> sqlQuote (T.pack (show cutoff))]

buildDailyReport :: DailyReportConfig -> Day -> IO Text
buildDailyReport DailyReportConfig {..} day = do
  let start = T.pack (show day) <> "T00:00:00Z"
  let end = T.pack (show (addDays 1 day)) <> "T00:00:00Z"
  opened <- (sqliteQuery ("SELECT severity, component, summary, first_seen, resolved_at FROM incidents WHERE first_seen >= " <> sqlQuote start <> " AND first_seen < " <> sqlQuote end) :: IO [SummaryRow])
  resolvedRows <- (sqliteQuery ("SELECT COUNT(*) AS count FROM incidents WHERE resolved_at IS NOT NULL AND resolved_at >= " <> sqlQuote start <> " AND resolved_at < " <> sqlQuote end) :: IO [CountRow])
  activeAtEnd <- (sqliteQuery ("SELECT severity, component, summary, first_seen, resolved_at FROM incidents WHERE first_seen < " <> sqlQuote end <> " AND (resolved_at IS NULL OR resolved_at >= " <> sqlQuote end <> ")") :: IO [SummaryRow])
  let openedCount = length opened
  let resolvedCount = case resolvedRows of CountRow n : _ -> n; _ -> 0
  let severityCounts = Map.fromListWith (+) [(severityText (srSeverity row), 1 :: Int) | row <- opened]
  let componentCounts = take reportComponentLimit . sortOn (Down . snd) . Map.toList $ Map.fromListWith (+) [(srComponent row, 1 :: Int) | row <- opened]
  let activeTop = take reportActiveLimit activeAtEnd
  pure . T.unlines $
    [ "Daily monitor summary for " <> T.pack (show day)
    , "Opened: " <> T.pack (show openedCount) <> " | Resolved: " <> T.pack (show resolvedCount) <> " | Still active at end of day: " <> T.pack (show (length activeAtEnd))
    , ""
    , "Opened by severity: " <> formatCounts severityCounts
    , "Top affected components: " <> if null componentCounts then "none" else T.intercalate ", " [name <> " (" <> T.pack (show count) <> ")" | (name, count) <- componentCounts]
    ]
    <> if null activeTop
         then ["", "Active at end of day: none"]
         else ["", "Active at end of day:"] <> ["- [" <> severityText (srSeverity row) <> "] " <> srComponent row <> ": " <> srSummary row | row <- activeTop]

formatCounts :: Map Text Int -> Text
formatCounts counts
  | Map.null counts = "none"
  | otherwise = T.intercalate ", " [k <> "=" <> T.pack (show v) | (k, v) <- Map.toList counts]

sendIssueMessage :: Text -> Text -> Text -> [Issue] -> IO ()
sendIssueMessage token chatId title issues = do
  now <- getCurrentTime
  sendTelegramText token chatId (buildIssueMessage now title issues)

sendResolvedMessage :: Text -> Text -> Text -> [OpenIncident] -> IO ()
sendResolvedMessage token chatId title rows = do
  now <- getCurrentTime
  sendTelegramText token chatId (buildResolvedMessage now title rows)

sendTelegramText :: Text -> Text -> Text -> IO ()
sendTelegramText token chatId msg = forM_ (chunkMessage 3500 msg) $ \chunk -> do
  manager <- newManager tlsManagerSettings
  req0 <- parseRequest ("https://api.telegram.org/bot" <> T.unpack token <> "/sendMessage")
  let body = encode $ object ["chat_id" .= chatId, "text" .= chunk, "disable_web_page_preview" .= True]
  let req = req0 { method = "POST", requestHeaders = [("Content-Type", "application/json")], requestBody = RequestBodyLBS body }
  res <- httpLbs req manager
  let code = statusCode (responseStatus res)
  unless (code >= 200 && code < 300) $ error ("telegram send failed with status " <> show code)

buildIssueMessage :: UTCTime -> Text -> [Issue] -> Text
buildIssueMessage now title issues = T.unlines $
  [title <> " at " <> isoZ now]
  <> ["- [" <> severityText (severity issue) <> "] " <> component issue <> ": " <> summary issue <> ". " <> detail issue | issue <- issues]

buildResolvedMessage :: UTCTime -> Text -> [OpenIncident] -> Text
buildResolvedMessage now title incidents = T.unlines $
  [title <> " at " <> isoZ now]
  <> ["- [" <> severityText (oiSeverity row) <> "] " <> oiComponent row <> ": " <> oiSummary row | row <- incidents]

sortIssues :: [Issue] -> [Issue]
sortIssues = sortOn (\i -> (Down (severity i), component i, summary i))

isGroupWorthy :: Issue -> Bool
isGroupWorthy Issue {..}
  | severity /= Critical = False
  | otherwise = category `elem`
      [ CatSystemState
      , CatSystemPort
      , CatSystemHealth
      , CatSystemResult
      , CatBotService
      , CatBotPort
      , CatBotConfigRead
      , CatBotConfigInvalid
      , CatBotUnknownModel
      , CatProviderStatus
      ]

incidentToIssue :: OpenIncident -> Issue
incidentToIssue OpenIncident {..} =
  Issue oiIssueId oiSeverity oiComponent oiSummary oiDetail CatProviderPoll Nothing

containsAny :: Text -> [Text] -> Bool
containsAny haystack needles = any (`T.isInfixOf` haystack) needles

uniqueUnknownModels :: Text -> [Text]
uniqueUnknownModels logs = nub (mapMaybe extract (T.lines logs))
  where
    marker = "Unknown model: "
    extract line =
      let (_, suffix) = T.breakOn marker line
       in if T.null suffix
            then Nothing
            else Just (T.strip (T.takeWhile (/= '"') (T.drop (T.length marker) suffix)))

lookupText :: Text -> Object -> Text
lookupText key obj = fromMaybe "" (KeyMap.lookup (Key.fromText key) obj >>= valueText)

slugify :: Text -> Text
slugify = trimDashes . squeezeDashes . T.map normalize . T.toLower
  where
    normalize c | isAlphaNum c = c
                | otherwise = '-'
    squeezeDashes = T.pack . reverse . foldl step [] . T.unpack
    step ('-' : rest) '-' = '-' : rest
    step acc ch = ch : acc
    trimDashes = T.dropWhileEnd (== '-') . T.dropWhile (== '-')

renderJsonValue :: Value -> Text
renderJsonValue = TE.decodeUtf8 . LBS.toStrict . encode

parseReportTime :: Text -> (Int, Int)
parseReportTime raw =
  case map readMaybe (splitOn ':' (T.unpack raw)) of
    [Just hh, Just mm] -> (hh, mm)
    _ -> (0, 0)

splitOn :: Char -> String -> [String]
splitOn delim s = case dropWhile (== delim) s of
  "" -> []
  s' -> let (w, rest) = break (== delim) s' in w : splitOn delim rest

runCommandCapture :: [String] -> IO (ExitCode, String, String)
runCommandCapture [] = pure (ExitFailure 1, "", "empty command")
runCommandCapture (cmd : args) = readProcessWithExitCode cmd args ""

httpGetJson :: Text -> IO Value
httpGetJson url = do
  manager <- newManager tlsManagerSettings
  req0 <- parseRequest (T.unpack url)
  let req = req0 { requestHeaders = ("User-Agent", "braiins-monitor/2.0") : requestHeaders req0 }
  res <- httpLbs req manager
  let code = statusCode (responseStatus res)
  unless (code >= 200 && code < 300) $ error ("http get failed with status " <> show code)
  case eitherDecode (responseBody res) of
    Left err -> error err
    Right value -> pure value

chunkMessage :: Int -> Text -> [Text]
chunkMessage limit msg
  | T.length msg <= limit = [msg]
  | otherwise = go (T.lines msg)
  where
    go [] = []
    go xs =
      let (chunkLines, rest) = takeChunk [] 0 xs
       in T.unlines chunkLines : go rest
    takeChunk acc _ [] = (reverse acc, [])
    takeChunk [] _ (l : ls) = takeChunk [l] (T.length l + 1) ls
    takeChunk acc n (l : ls)
      | n + T.length l + 1 <= limit = takeChunk (l : acc) (n + T.length l + 1) ls
      | otherwise = (reverse acc, l : ls)

trim :: String -> String
trim = f . f
  where
    f = reverse . dropWhile (`elem` ['\n', '\r', ' ', '\t'])

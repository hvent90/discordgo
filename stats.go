package discordgo

import (
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

const dimension = "1"

var (
	mGuildCreate       = stats.Int64("GuildCreate", "GuildCreate", dimension)
	mGuildUpdate       = stats.Int64("GuildUpdate", "GuildUpdate", dimension)
	mGuildDelete       = stats.Int64("GuildDelete", "GuildDelete", dimension)
	mGuildMemberAdd    = stats.Int64("GuildMemberAdd", "GuildMemberAdd", dimension)
	mGuildMemberUpdate = stats.Int64("GuildMemberUpdate", "GuildMemberUpdate", dimension)
	mGuildMemberRemove = stats.Int64("GuildMemberRemove", "GuildMemberRemove", dimension)
	mGuildMembersChunk = stats.Int64("GuildMembersChunk", "GuildMembersChunk", dimension)
	mGuildRoleCreate   = stats.Int64("GuildRoleCreate", "GuildRoleCreate", dimension)
	mGuildRoleUpdate   = stats.Int64("GuildRoleUpdate", "GuildRoleUpdate", dimension)
	mGuildRoleDelete   = stats.Int64("GuildRoleDelete", "GuildRoleDelete", dimension)
	mGuildEmojisUpdate = stats.Int64("GuildEmojisUpdate", "GuildEmojisUpdate", dimension)
	mChannelCreate     = stats.Int64("ChannelCreate", "ChannelCreate", dimension)
	mChannelUpdate     = stats.Int64("ChannelUpdate", "ChannelUpdate", dimension)
	mChannelDelete     = stats.Int64("ChannelDelete", "ChannelDelete", dimension)
	mMessageCreate     = stats.Int64("MessageCreate", "MessageCreate", dimension)
	mMessageUpdate     = stats.Int64("MessageUpdate", "MessageUpdate", dimension)
	mMessageDelete     = stats.Int64("MessageDelete", "MessageDelete", dimension)
	mMessageDeleteBulk = stats.Int64("MessageDeleteBulk", "MessageDeleteBulk", dimension)
	mVoiceStateUpdate  = stats.Int64("VoiceStateUpdate", "VoiceStateUpdate", dimension)
	mPresenceUpdate    = stats.Int64("PresenceUpdate", "PresenceUpdate", dimension)
)

var AllViews = []*view.View{
	{Name: "discordgo/GuildCreate", Description: "Tracks the number of invocations of GuildCreate", Measure: mGuildCreate, Aggregation: view.Count()},
	{Name: "discordgo/GuildUpdate", Description: "Tracks the number of invocations of GuildUpdate", Measure: mGuildUpdate, Aggregation: view.Count()},
	{Name: "discordgo/GuildDelete", Description: "Tracks the number of invocations of GuildDelete", Measure: mGuildDelete, Aggregation: view.Count()},
	{Name: "discordgo/GuildMemberAdd", Description: "Tracks the number of invocations of GuildMemberAdd", Measure: mGuildMemberAdd, Aggregation: view.Count()},
	{Name: "discordgo/GuildMemberUpdate", Description: "Tracks the number of invocations of GuildMemberUpdate", Measure: mGuildMemberUpdate, Aggregation: view.Count()},
	{Name: "discordgo/GuildMemberRemove", Description: "Tracks the number of invocations of GuildMemberRemove", Measure: mGuildMemberRemove, Aggregation: view.Count()},
	{Name: "discordgo/GuildMembersChunk", Description: "Tracks the number of invocations of GuildMembersChunk", Measure: mGuildMembersChunk, Aggregation: view.Count()},
	{Name: "discordgo/GuildRoleCreate", Description: "Tracks the number of invocations of GuildRoleCreate", Measure: mGuildRoleCreate, Aggregation: view.Count()},
	{Name: "discordgo/GuildRoleUpdate", Description: "Tracks the number of invocations of GuildRoleUpdate", Measure: mGuildRoleUpdate, Aggregation: view.Count()},
	{Name: "discordgo/GuildRoleDelete", Description: "Tracks the number of invocations of GuildRoleDelete", Measure: mGuildRoleDelete, Aggregation: view.Count()},
	{Name: "discordgo/GuildEmojisUpdate", Description: "Tracks the number of invocations of GuildEmojisUpdate", Measure: mGuildEmojisUpdate, Aggregation: view.Count()},
	{Name: "discordgo/ChannelCreate", Description: "Tracks the number of invocations of ChannelCreate", Measure: mChannelCreate, Aggregation: view.Count()},
	{Name: "discordgo/ChannelUpdate", Description: "Tracks the number of invocations of ChannelUpdate", Measure: mChannelUpdate, Aggregation: view.Count()},
	{Name: "discordgo/ChannelDelete", Description: "Tracks the number of invocations of ChannelDelete", Measure: mChannelDelete, Aggregation: view.Count()},
	{Name: "discordgo/MessageCreate", Description: "Tracks the number of invocations of MessageCreate", Measure: mMessageCreate, Aggregation: view.Count()},
	{Name: "discordgo/MessageUpdate", Description: "Tracks the number of invocations of MessageUpdate", Measure: mMessageUpdate, Aggregation: view.Count()},
	{Name: "discordgo/MessageDelete", Description: "Tracks the number of invocations of MessageDelete", Measure: mMessageDelete, Aggregation: view.Count()},
	{Name: "discordgo/MessageDeleteBulk", Description: "Tracks the number of invocations of MessageDeleteBulk", Measure: mMessageDeleteBulk, Aggregation: view.Count()},
	{Name: "discordgo/VoiceStateUpdate", Description: "Tracks the number of invocations of VoiceStateUpdate", Measure: mVoiceStateUpdate, Aggregation: view.Count()},
	{Name: "discordgo/PresenceUpdate", Description: "Tracks the number of invocations of PresenceUpdate", Measure: mPresenceUpdate, Aggregation: view.Count()},
}

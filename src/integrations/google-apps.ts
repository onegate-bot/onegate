/**
 * Google scope packs: selectable per-product scope bundles for the single
 * Google OAuth consent. The connect dialog renders these as checkboxes and
 * the union of the selected packs' scopes is requested at consent time.
 *
 * Identity scopes are intentionally left out (the gateway never fetches
 * userinfo) and the packs are aligned with OneGate's host list.
 */

import type { ScopePack } from "./types.js";

const A = "https://www.googleapis.com/auth/";

export const GOOGLE_APPS: ScopePack[] = [
  {
    id: "gmail",
    label: "Gmail",
    description: "Read, organize and send email",
    default: true,
    scopes: [`${A}gmail.modify`],
    permissions: [
      { scope: `${A}gmail.modify`, name: "Email", description: "Read, label, draft and organize messages", access: "write" },
    ],
  },
  {
    id: "calendar",
    label: "Calendar",
    description: "Read and manage calendars and events",
    default: true,
    scopes: [`${A}calendar`],
    permissions: [
      { scope: `${A}calendar`, name: "Calendars", description: "View and edit events on all calendars", access: "write" },
    ],
  },
  {
    id: "drive",
    label: "Drive",
    description: "Read and manage files in Google Drive",
    default: true,
    scopes: [`${A}drive`],
    permissions: [
      { scope: `${A}drive`, name: "Files", description: "View, create and edit all Drive files", access: "write" },
    ],
  },
  {
    id: "docs",
    label: "Docs",
    description: "Create and edit Google Docs documents",
    scopes: [`${A}documents`],
    permissions: [
      { scope: `${A}documents`, name: "Documents", description: "View and edit documents", access: "write" },
    ],
  },
  {
    id: "sheets",
    label: "Sheets",
    description: "Create and edit spreadsheets",
    scopes: [`${A}spreadsheets`],
    permissions: [
      { scope: `${A}spreadsheets`, name: "Spreadsheets", description: "View and edit spreadsheets", access: "write" },
    ],
  },
  {
    id: "slides",
    label: "Slides",
    description: "Build and revise presentations",
    scopes: [`${A}presentations`],
    permissions: [
      { scope: `${A}presentations`, name: "Presentations", description: "View and edit presentations", access: "write" },
    ],
  },
  {
    id: "forms",
    label: "Forms",
    description: "Create forms and read responses",
    scopes: [`${A}forms.body`, `${A}forms.responses.readonly`],
    permissions: [
      { scope: `${A}forms.body`, name: "Forms", description: "Create and edit forms", access: "write" },
      { scope: `${A}forms.responses.readonly`, name: "Responses", description: "Read form responses", access: "read" },
    ],
  },
  {
    id: "tasks",
    label: "Tasks",
    description: "Work with tasks and their lists",
    scopes: [`${A}tasks`],
    permissions: [
      { scope: `${A}tasks`, name: "Tasks", description: "Create, edit and complete tasks", access: "write" },
    ],
  },
  {
    id: "meet",
    label: "Meet",
    description: "Create meeting spaces and read meeting artifacts",
    scopes: [`${A}meetings.space.created`, `${A}meetings.space.readonly`],
    permissions: [
      { scope: `${A}meetings.space.created`, name: "Meetings", description: "Open and administer meeting spaces", access: "write" },
      { scope: `${A}meetings.space.readonly`, name: "Meeting info", description: "Read meeting space details", access: "read" },
    ],
  },
  {
    id: "chat",
    label: "Chat",
    description: "Read and send Google Chat messages",
    scopes: [`${A}chat.spaces`, `${A}chat.messages`, `${A}chat.memberships`],
    permissions: [
      { scope: `${A}chat.spaces`, name: "Spaces", description: "View and manage Chat spaces", access: "write" },
      { scope: `${A}chat.messages`, name: "Messages", description: "Read and send messages", access: "write" },
      { scope: `${A}chat.memberships`, name: "Members", description: "View and manage space members", access: "write" },
    ],
  },
  {
    id: "photos",
    label: "Photos",
    description: "Access the Google Photos library",
    scopes: [`${A}photoslibrary`],
    permissions: [
      { scope: `${A}photoslibrary`, name: "Photo library", description: "View and organize photos and albums", access: "write" },
    ],
  },
  {
    id: "classroom",
    label: "Classroom",
    description: "Manage Classroom courses and rosters",
    scopes: [`${A}classroom.courses`, `${A}classroom.rosters.readonly`],
    permissions: [
      { scope: `${A}classroom.courses`, name: "Courses", description: "View and manage courses", access: "write" },
      { scope: `${A}classroom.rosters.readonly`, name: "Rosters", description: "Read class rosters", access: "read" },
    ],
  },
  {
    id: "admin",
    label: "Workspace Admin",
    description: "Manage Workspace users (directory)",
    scopes: [`${A}admin.directory.user`],
    permissions: [
      { scope: `${A}admin.directory.user`, name: "Directory users", description: "View and manage user accounts", access: "write" },
    ],
  },
  {
    id: "analytics",
    label: "Analytics",
    description: "Read Google Analytics data",
    scopes: [`${A}analytics.readonly`],
    permissions: [
      { scope: `${A}analytics.readonly`, name: "Analytics data", description: "Read reports and configuration", access: "read" },
    ],
  },
  {
    id: "search-console",
    label: "Search Console",
    description: "Read and manage Search Console properties",
    scopes: [`${A}webmasters`],
    permissions: [
      { scope: `${A}webmasters`, name: "Search data", description: "View and manage Search Console data", access: "write" },
    ],
  },
  {
    id: "youtube",
    label: "YouTube",
    description: "Manage a YouTube account",
    scopes: [`${A}youtube`],
    permissions: [
      { scope: `${A}youtube`, name: "YouTube account", description: "View and manage videos, playlists and channel data", access: "write" },
    ],
  },
];

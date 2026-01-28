// ===================================================================
// iAPP PRO V5.0 - BACKEND
// Phiên bản: 5.0.0 | Ngày: 2025
// Tái cấu trúc hoàn toàn - Modular & Safe
// ===================================================================

// ===================================================================
// 1. CẤU HÌNH HỆ THỐNG
// ===================================================================
const CONFIG = {
  VERSION: '5.0.0',
  SHEETS: {
    APPS: 'DB_Apps',
    USERS: 'DB_Users',
    SESSIONS: 'DB_Sessions',
    CATEGORIES: 'DB_Categories',
    COMMENTS: 'DB_Comments',
    FAVORITES: 'DB_Favorites',
    RATINGS: 'DB_Ratings',
    LOGS: 'DB_Logs',
    CONTACTS: 'DB_Contacts',
    NOTIFICATIONS: 'DB_Notifications',
    PERMISSIONS: 'DB_AppPermissions'
  },
  SESSION_DURATION: 24 * 60 * 60 * 1000,
  MAX_LOGIN_ATTEMPTS: 5,
  LOCK_DURATION: 30 * 60 * 1000,
  DEFAULT_ADMIN: {
    username: 'admin',
    password: 'Admin@123',
    displayName: 'Administrator'
  }
};

const ROLES = {
  ADMIN: 'Admin',
  MANAGER: 'Manager',
  USER: 'User',
  GUEST: 'Guest'
};

// ===================================================================
// 2. WEB APP ENTRY POINTS
// ===================================================================
function doGet(e) {
  try {
    const template = HtmlService.createTemplateFromFile('Index');
    return template.evaluate()
      .setTitle('iApp Pro V5.0')
      .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL)
      .addMetaTag('viewport', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no')
      .setFaviconUrl('https://cdn-icons-png.flaticon.com/128/8633/8633210.png');
  } catch (error) {
    Logger.log('doGet error: ' + error.message);
    return HtmlService.createHtmlOutput('<h1>Lỗi khởi tạo ứng dụng</h1><p>' + error.message + '</p>');
  }
}

function include(filename) {
  try {
    return HtmlService.createHtmlOutputFromFile(filename).getContent();
  } catch (error) {
    Logger.log('Include error for ' + filename + ': ' + error.message);
    return '<!-- Error loading ' + filename + ' -->';
  }
}

// ===================================================================
// 3. UTILITY FUNCTIONS
// ===================================================================
const Utils = {
  // Tạo ID unique
  generateId(prefix) {
    return prefix + '_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  },

  // Tạo salt cho password
  generateSalt() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let salt = '';
    for (let i = 0; i < 32; i++) {
      salt += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return salt;
  },

  // Hash password với salt
  hashPassword(password, salt) {
    const combined = salt + password + salt;
    const hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, combined);
    return hash.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
  },

  // Validate URL
  isValidURL(str) {
    if (!str || typeof str !== 'string') return false;
    try {
      const url = new URL(str.trim());
      return ['http:', 'https:'].includes(url.protocol);
    } catch {
      return false;
    }
  },

  // Validate Email
  isValidEmail(str) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
  },

  // Safe JSON parse
  safeJSONParse(str, defaultVal = null) {
    try {
      return str ? JSON.parse(str) : defaultVal;
    } catch {
      return defaultVal;
    }
  },

  // Safe JSON stringify
  safeJSONStringify(obj) {
    try {
      return JSON.stringify(obj);
    } catch {
      return '{}';
    }
  },

  // Lấy nội dung từ JSON hoặc plain text
  getContent(value) {
    if (!value) return '';
    if (typeof value !== 'string') return String(value);
    const trimmed = value.trim();
    if (!trimmed.startsWith('{')) return trimmed;
    try {
      const parsed = JSON.parse(trimmed);
      return parsed.content || parsed.text || trimmed;
    } catch {
      return trimmed;
    }
  }
};

// ===================================================================
// 4. DATABASE LAYER
// ===================================================================
const DB = {
  _ss: null,
  _cache: {},

  // Lấy Spreadsheet
  getSpreadsheet() {
    if (!this._ss) {
      this._ss = SpreadsheetApp.getActiveSpreadsheet();
    }
    return this._ss;
  },

  // Lấy Sheet theo tên
  getSheet(sheetName) {
    return this.getSpreadsheet().getSheetByName(sheetName);
  },

  // Lấy tất cả dữ liệu từ sheet (có cache)
  getAll(sheetName, useCache = false) {
    if (useCache && this._cache[sheetName]) {
      return this._cache[sheetName];
    }
    
    const sheet = this.getSheet(sheetName);
    if (!sheet) return { headers: [], rows: [] };
    
    const data = sheet.getDataRange().getValues();
    const headers = data[0] || [];
    const rows = data.slice(1);
    
    const result = { headers, rows, sheet };
    if (useCache) this._cache[sheetName] = result;
    return result;
  },

  // Tìm row theo điều kiện
  findRow(sheetName, columnName, value) {
    const { headers, rows, sheet } = this.getAll(sheetName);
    const colIndex = headers.indexOf(columnName);
    if (colIndex === -1) return null;
    
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][colIndex] === value) {
        return { index: i + 2, data: rows[i], headers, sheet }; // +2 vì row 1 là header
      }
    }
    return null;
  },

  // Tìm nhiều rows
  findRows(sheetName, columnName, value) {
    const { headers, rows } = this.getAll(sheetName);
    const colIndex = headers.indexOf(columnName);
    if (colIndex === -1) return [];
    
    return rows
      .map((row, i) => ({ index: i + 2, data: row, headers }))
      .filter(item => item.data[colIndex] === value);
  },

  // Thêm row mới
  appendRow(sheetName, rowData) {
    const sheet = this.getSheet(sheetName);
    if (!sheet) return false;
    sheet.appendRow(rowData);
    this._cache[sheetName] = null; // Clear cache
    return true;
  },

  // Cập nhật cell
  updateCell(sheetName, rowIndex, colIndex, value) {
    const sheet = this.getSheet(sheetName);
    if (!sheet) return false;
    sheet.getRange(rowIndex, colIndex + 1).setValue(value);
    this._cache[sheetName] = null;
    return true;
  },

  // Cập nhật nhiều cells trong 1 row
  updateRow(sheetName, rowIndex, updates, headers) {
    const sheet = this.getSheet(sheetName);
    if (!sheet) return false;
    
    for (const [colName, value] of Object.entries(updates)) {
      const colIndex = headers.indexOf(colName);
      if (colIndex !== -1) {
        sheet.getRange(rowIndex, colIndex + 1).setValue(value);
      }
    }
    this._cache[sheetName] = null;
    return true;
  },

  // Xóa row
  deleteRow(sheetName, rowIndex) {
    const sheet = this.getSheet(sheetName);
    if (!sheet) return false;
    sheet.deleteRow(rowIndex);
    this._cache[sheetName] = null;
    return true;
  },

  // Clear cache
  clearCache() {
    this._cache = {};
  }
};

// ===================================================================
// 5. LOGGING
// ===================================================================
function logActivity(userId, action, details, result) {
  try {
    DB.appendRow(CONFIG.SHEETS.LOGS, [
      Utils.generateId('LOG'),
      new Date().toISOString(),
      userId || 'SYSTEM',
      action,
      details,
      result,
      ''
    ]);
  } catch (e) {
    Logger.log('Log error: ' + e.message);
  }
}

// ===================================================================
// 6. AUTHENTICATION MODULE
// ===================================================================
const Auth = {
  // Đăng nhập
  login(username, password) {
    try {
      if (!username || !password) {
        return { success: false, error: 'Vui lòng nhập đầy đủ thông tin' };
      }

      const userResult = DB.findRow(CONFIG.SHEETS.USERS, 'Username', username.toLowerCase());
      
      if (!userResult) {
        logActivity(null, 'LOGIN_FAILED', 'Username không tồn tại: ' + username, 'Failed');
        return { success: false, error: 'Tên đăng nhập hoặc mật khẩu không đúng' };
      }

      const { index, data, headers, sheet } = userResult;
      const getCol = (name) => headers.indexOf(name);

      // Kiểm tra trạng thái
      if (data[getCol('Status')] === 'Inactive') {
        return { success: false, error: 'Tài khoản đã bị vô hiệu hóa' };
      }

      // Kiểm tra khóa
      const lockedUntil = data[getCol('LockedUntil')];
      if (lockedUntil && new Date(lockedUntil) > new Date()) {
        const mins = Math.ceil((new Date(lockedUntil) - new Date()) / 60000);
        return { success: false, error: 'Tài khoản đang bị khóa. Thử lại sau ' + mins + ' phút' };
      }

      // Xác thực password
      const salt = data[getCol('Salt')];
      const storedHash = data[getCol('PasswordHash')];
      const inputHash = Utils.hashPassword(password, salt);

      if (inputHash !== storedHash) {
        const attempts = (parseInt(data[getCol('FailedAttempts')]) || 0) + 1;
        DB.updateCell(CONFIG.SHEETS.USERS, index, getCol('FailedAttempts'), attempts);

        if (attempts >= CONFIG.MAX_LOGIN_ATTEMPTS) {
          const lockTime = new Date(Date.now() + CONFIG.LOCK_DURATION).toISOString();
          DB.updateCell(CONFIG.SHEETS.USERS, index, getCol('LockedUntil'), lockTime);
          return { success: false, error: 'Tài khoản đã bị khóa do đăng nhập sai quá nhiều' };
        }

        return { success: false, error: 'Mật khẩu không đúng. Còn ' + (CONFIG.MAX_LOGIN_ATTEMPTS - attempts) + ' lần thử' };
      }

      // Đăng nhập thành công
      DB.updateRow(CONFIG.SHEETS.USERS, index, {
        'FailedAttempts': 0,
        'LockedUntil': '',
        'LastLogin': new Date().toISOString()
      }, headers);

      // Tạo session
      const sessionId = this.createSession(data[getCol('UserID')]);

      logActivity(data[getCol('UserID')], 'LOGIN_SUCCESS', 'Đăng nhập thành công', 'Success');

      return {
        success: true,
        sessionId: sessionId,
        user: {
          id: data[getCol('UserID')],
          username: data[getCol('Username')],
          displayName: data[getCol('DisplayName')],
          email: data[getCol('Email')],
          role: data[getCol('Role')]
        }
      };

    } catch (e) {
      Logger.log('Login error: ' + e.message);
      return { success: false, error: 'Lỗi hệ thống: ' + e.message };
    }
  },

  // Đăng nhập Guest
  loginAsGuest() {
    try {
      const sessionId = this.createSession('GUEST');
      logActivity('GUEST', 'GUEST_LOGIN', 'Đăng nhập khách', 'Success');
      
      return {
        success: true,
        sessionId: sessionId,
        user: {
          id: 'GUEST',
          username: 'guest',
          displayName: 'Khách',
          role: ROLES.GUEST
        }
      };
    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Tạo session
  createSession(userId) {
    const sessionId = 'SES_' + Utilities.getUuid().replace(/-/g, '');
    
    // Vô hiệu hóa session cũ
    this.invalidateUserSessions(userId);
    
    DB.appendRow(CONFIG.SHEETS.SESSIONS, [
      sessionId,
      userId,
      new Date().toISOString(),
      new Date(Date.now() + CONFIG.SESSION_DURATION).toISOString(),
      '',
      '',
      true
    ]);

    return sessionId;
  },

  // Vô hiệu hóa sessions cũ
  invalidateUserSessions(userId) {
    const { headers, rows, sheet } = DB.getAll(CONFIG.SHEETS.SESSIONS);
    const userIdCol = headers.indexOf('UserID');
    const validCol = headers.indexOf('IsValid');
    
    rows.forEach((row, i) => {
      if (row[userIdCol] === userId && row[validCol] === true) {
        sheet.getRange(i + 2, validCol + 1).setValue(false);
      }
    });
  },

  // Xác thực session
  validateSession(sessionId) {
    try {
      if (!sessionId) {
        return { valid: false, error: 'Không có session' };
      }

      const result = DB.findRow(CONFIG.SHEETS.SESSIONS, 'SessionID', sessionId);
      if (!result) {
        return { valid: false, error: 'Session không tồn tại' };
      }

      const { index, data, headers, sheet } = result;
      const getCol = (name) => headers.indexOf(name);

      if (data[getCol('IsValid')] !== true) {
        return { valid: false, error: 'Session đã hết hiệu lực' };
      }

      if (new Date(data[getCol('ExpiresAt')]) < new Date()) {
        DB.updateCell(CONFIG.SHEETS.SESSIONS, index, getCol('IsValid'), false);
        return { valid: false, error: 'Session đã hết hạn' };
      }

      const userId = data[getCol('UserID')];

      // Guest user
      if (userId === 'GUEST') {
        return {
          valid: true,
          user: {
            id: 'GUEST',
            username: 'guest',
            displayName: 'Khách',
            role: ROLES.GUEST
          }
        };
      }

      // Regular user
      const userResult = DB.findRow(CONFIG.SHEETS.USERS, 'UserID', userId);
      if (!userResult) {
        return { valid: false, error: 'User không tồn tại' };
      }

      const userData = userResult.data;
      const userHeaders = userResult.headers;
      const getUserCol = (name) => userHeaders.indexOf(name);

      return {
        valid: true,
        user: {
          id: userData[getUserCol('UserID')],
          username: userData[getUserCol('Username')],
          displayName: userData[getUserCol('DisplayName')],
          email: userData[getUserCol('Email')],
          role: userData[getUserCol('Role')]
        }
      };

    } catch (e) {
      Logger.log('ValidateSession error: ' + e.message);
      return { valid: false, error: 'Lỗi hệ thống' };
    }
  },

  // Đăng xuất
  logout(sessionId) {
    try {
      const result = DB.findRow(CONFIG.SHEETS.SESSIONS, 'SessionID', sessionId);
      if (result) {
        const validCol = result.headers.indexOf('IsValid');
        DB.updateCell(CONFIG.SHEETS.SESSIONS, result.index, validCol, false);
        logActivity(result.data[result.headers.indexOf('UserID')], 'LOGOUT', 'Đăng xuất', 'Success');
      }
      return { success: true };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
};

// Expose Auth functions
function login(username, password) {
  return Auth.login(username, password);
}

function loginAsGuest() {
  return Auth.loginAsGuest();
}

function validateSession(sessionId) {
  return Auth.validateSession(sessionId);
}

function logout(sessionId) {
  return Auth.logout(sessionId);
}

// ===================================================================
// 7. DATA ACCESS MODULE
// ===================================================================
const DataAccess = {
  // Lấy dữ liệu ban đầu
  getInitialData(sessionId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, requiresAuth: true, error: sessionResult.error };
      }

      const user = sessionResult.user;
      const apps = this.getAppsForUser(user);
      const categories = this.getCategories();
      const users = user.role === ROLES.ADMIN ? this.getUsers() : [];
      const favorites = user.id !== 'GUEST' ? this.getUserFavorites(user.id) : [];
      const ratings = this.getAllRatings(user.id);
      const permissions = this.getUserPermissions(user);

      // Thống kê
      const stats = {
        totalApps: apps.length,
        totalUsers: users.length,
        totalViews: apps.reduce((sum, app) => sum + (parseInt(app.views) || 0), 0),
        categoryCounts: {}
      };

      apps.forEach(app => {
        const cat = app.category || 'Khác';
        stats.categoryCounts[cat] = (stats.categoryCounts[cat] || 0) + 1;
      });

      return {
        success: true,
        user: user,
        apps: apps,
        categories: categories,
        users: users,
        favorites: favorites,
        ratings: ratings,
        permissions: permissions,
        stats: stats,
        version: CONFIG.VERSION
      };

    } catch (e) {
      Logger.log('getInitialData error: ' + e.message);
      return { success: false, error: 'Lỗi tải dữ liệu: ' + e.message };
    }
  },

  // Lấy danh sách apps theo quyền user
  getAppsForUser(user) {
    const { headers, rows } = DB.getAll(CONFIG.SHEETS.APPS);
    const getCol = (name) => headers.indexOf(name);
    const apps = [];

    rows.forEach(row => {
      if (!row[getCol('ID')]) return;
      if (row[getCol('Status')] !== 'Active') return;

      const visibility = row[getCol('Visibility')] || 'Private';
      let canView = false;
      let canEdit = false;
      let canDelete = false;

      switch (user.role) {
        case ROLES.ADMIN:
          canView = canEdit = canDelete = true;
          break;
        case ROLES.MANAGER:
          canView = true;
          canEdit = canDelete = (row[getCol('CreatedBy')] === user.id);
          break;
        case ROLES.USER:
          canView = ['Public', 'User', 'Guest'].includes(visibility);
          break;
        case ROLES.GUEST:
          canView = ['Public', 'Guest'].includes(visibility);
          break;
      }

      if (canView) {
        const appId = row[getCol('ID')];
        const ratingData = this.calculateRating(appId);

        apps.push({
          id: appId,
          name: row[getCol('Name')],
          link: row[getCol('Link')],
          description: Utils.getContent(row[getCol('Description')]),
          category: row[getCol('Category')],
          imageURL: row[getCol('ImageURL')],
          visibility: visibility,
          createdBy: row[getCol('CreatedBy')],
          createdAt: row[getCol('CreatedAt')],
          updatedAt: row[getCol('UpdatedAt')],
          views: parseInt(row[getCol('Views')]) || 0,
          videoURL: row[getCol('VideoURL')] || '',
          tags: row[getCol('Tags')] || '',
          canEdit: canEdit,
          canDelete: canDelete,
          avgRating: ratingData.average,
          ratingCount: ratingData.count
        });
      }
    });

    return apps;
  },

  // Lấy danh mục
  getCategories() {
    const { headers, rows } = DB.getAll(CONFIG.SHEETS.CATEGORIES);
    const getCol = (name) => headers.indexOf(name);
    
    return rows
      .filter(row => row[getCol('ID')] && row[getCol('Status')] !== 'Inactive')
      .map(row => ({
        id: row[getCol('ID')],
        name: row[getCol('Name')],
        icon: row[getCol('Icon')] || 'fa-folder',
        description: row[getCol('Description')],
        sortOrder: parseInt(row[getCol('SortOrder')]) || 0
      }))
      .sort((a, b) => a.sortOrder - b.sortOrder);
  },

  // Lấy users (Admin only)
  getUsers() {
    const { headers, rows } = DB.getAll(CONFIG.SHEETS.USERS);
    const getCol = (name) => headers.indexOf(name);
    
    return rows
      .filter(row => row[getCol('UserID')])
      .map(row => ({
        id: row[getCol('UserID')],
        username: row[getCol('Username')],
        displayName: row[getCol('DisplayName')],
        email: row[getCol('Email')],
        role: row[getCol('Role')],
        status: row[getCol('Status')],
        createdAt: row[getCol('CreatedAt')],
        lastLogin: row[getCol('LastLogin')]
      }));
  },

  // Lấy favorites của user
  getUserFavorites(userId) {
    const results = DB.findRows(CONFIG.SHEETS.FAVORITES, 'UserID', userId);
    return results.map(r => r.data[r.headers.indexOf('AppID')]);
  },

  // Lấy tất cả ratings
  getAllRatings(userId) {
    const { headers, rows } = DB.getAll(CONFIG.SHEETS.RATINGS);
    const getCol = (name) => headers.indexOf(name);
    const ratingsMap = {};

    rows.forEach(row => {
      const appId = row[getCol('AppID')];
      const ratingUserId = row[getCol('UserID')];
      const stars = parseInt(row[getCol('Stars')]) || 0;

      if (!ratingsMap[appId]) {
        ratingsMap[appId] = { totalStars: 0, count: 0, userRating: 0 };
      }

      ratingsMap[appId].totalStars += stars;
      ratingsMap[appId].count++;

      if (ratingUserId === userId) {
        ratingsMap[appId].userRating = stars;
      }
    });

    const result = {};
    for (const appId in ratingsMap) {
      const data = ratingsMap[appId];
      result[appId] = {
        average: data.count > 0 ? Math.round((data.totalStars / data.count) * 10) / 10 : 0,
        count: data.count,
        userRating: data.userRating
      };
    }

    return result;
  },

  // Tính rating cho 1 app
  calculateRating(appId) {
    const results = DB.findRows(CONFIG.SHEETS.RATINGS, 'AppID', appId);
    if (results.length === 0) return { average: 0, count: 0 };

    const starsCol = results[0].headers.indexOf('Stars');
    const total = results.reduce((sum, r) => sum + (parseInt(r.data[starsCol]) || 0), 0);
    
    return {
      average: Math.round((total / results.length) * 10) / 10,
      count: results.length
    };
  },

  // Lấy quyền user
  getUserPermissions(user) {
    const perms = {
      canViewApps: true,
      canAddApps: false,
      canEditApps: false,
      canDeleteApps: false,
      canManageUsers: false,
      canManageCategories: false,
      canViewLogs: false,
      canComment: false
    };

    switch (user.role) {
      case ROLES.ADMIN:
        Object.keys(perms).forEach(k => perms[k] = true);
        break;
      case ROLES.MANAGER:
        perms.canAddApps = perms.canEditApps = perms.canDeleteApps = perms.canComment = true;
        break;
      case ROLES.USER:
        perms.canComment = true;
        break;
    }

    return perms;
  }
};

function getInitialData(sessionId) {
  return DataAccess.getInitialData(sessionId);
}

// ===================================================================
// 8. CRUD OPERATIONS
// ===================================================================
const AppCRUD = {
  // Lưu app (thêm mới hoặc cập nhật)
  save(sessionId, appData, isNew) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      const permissions = DataAccess.getUserPermissions(user);

      if (isNew && !permissions.canAddApps) {
        return { success: false, error: 'Không có quyền thêm ứng dụng' };
      }

      if (!appData.name || appData.name.trim() === '') {
        return { success: false, error: 'Tên ứng dụng không được để trống' };
      }

      if (appData.link && !Utils.isValidURL(appData.link)) {
        return { success: false, error: 'URL không hợp lệ' };
      }

      const now = new Date().toISOString();
      const descJSON = JSON.stringify({
        content: appData.description || '',
        updatedAt: now,
        updatedBy: user.id
      });

      if (isNew) {
        const newId = Utils.generateId('APP');
        DB.appendRow(CONFIG.SHEETS.APPS, [
          newId,
          appData.name.trim(),
          appData.link || '',
          descJSON,
          appData.category || 'Khác',
          appData.imageURL || '',
          appData.visibility || 'Private',
          user.id,
          now,
          now,
          0,
          'Active',
          appData.videoURL || '',
          appData.tags || ''
        ]);

        logActivity(user.id, 'ADD_APP', 'Thêm: ' + appData.name, 'Success');
        return { success: true, appId: newId, message: 'Đã thêm ứng dụng' };

      } else {
        const result = DB.findRow(CONFIG.SHEETS.APPS, 'ID', appData.id);
        if (!result) {
          return { success: false, error: 'Không tìm thấy ứng dụng' };
        }

        // Kiểm tra quyền edit
        const createdByCol = result.headers.indexOf('CreatedBy');
        if (!permissions.canEditApps && result.data[createdByCol] !== user.id) {
          return { success: false, error: 'Không có quyền sửa ứng dụng này' };
        }

        DB.updateRow(CONFIG.SHEETS.APPS, result.index, {
          'Name': appData.name.trim(),
          'Link': appData.link || '',
          'Description': descJSON,
          'Category': appData.category || 'Khác',
          'ImageURL': appData.imageURL || '',
          'Visibility': appData.visibility || 'Private',
          'UpdatedAt': now,
          'VideoURL': appData.videoURL || '',
          'Tags': appData.tags || ''
        }, result.headers);

        logActivity(user.id, 'UPDATE_APP', 'Cập nhật: ' + appData.name, 'Success');
        return { success: true, message: 'Đã cập nhật ứng dụng' };
      }

    } catch (e) {
      Logger.log('SaveApp error: ' + e.message);
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Xóa app
  delete(sessionId, appId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      const result = DB.findRow(CONFIG.SHEETS.APPS, 'ID', appId);
      
      if (!result) {
        return { success: false, error: 'Không tìm thấy ứng dụng' };
      }

      const permissions = DataAccess.getUserPermissions(user);
      const createdByCol = result.headers.indexOf('CreatedBy');
      
      if (!permissions.canDeleteApps && result.data[createdByCol] !== user.id) {
        return { success: false, error: 'Không có quyền xóa ứng dụng này' };
      }

      const appName = result.data[result.headers.indexOf('Name')];
      DB.deleteRow(CONFIG.SHEETS.APPS, result.index);

      // Xóa comments, favorites liên quan
      this.deleteRelatedData(appId);

      logActivity(user.id, 'DELETE_APP', 'Xóa: ' + appName, 'Success');
      return { success: true, message: 'Đã xóa ứng dụng' };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Xóa dữ liệu liên quan
  deleteRelatedData(appId) {
    // Xóa favorites
    const favResults = DB.findRows(CONFIG.SHEETS.FAVORITES, 'AppID', appId);
    favResults.reverse().forEach(r => DB.deleteRow(CONFIG.SHEETS.FAVORITES, r.index));

    // Xóa ratings
    const ratingResults = DB.findRows(CONFIG.SHEETS.RATINGS, 'AppID', appId);
    ratingResults.reverse().forEach(r => DB.deleteRow(CONFIG.SHEETS.RATINGS, r.index));

    // Soft delete comments
    const cmtResults = DB.findRows(CONFIG.SHEETS.COMMENTS, 'AppID', appId);
    cmtResults.forEach(r => {
      const statusCol = r.headers.indexOf('Status');
      DB.updateCell(CONFIG.SHEETS.COMMENTS, r.index, statusCol, 'Deleted');
    });
  },

  // Tăng view
  incrementViews(sessionId, appId) {
    try {
      const result = DB.findRow(CONFIG.SHEETS.APPS, 'ID', appId);
      if (result) {
        const viewsCol = result.headers.indexOf('Views');
        const currentViews = parseInt(result.data[viewsCol]) || 0;
        DB.updateCell(CONFIG.SHEETS.APPS, result.index, viewsCol, currentViews + 1);
        return { success: true, views: currentViews + 1 };
      }
      return { success: false };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
};

function saveApp(sessionId, appData, isNew) {
  return AppCRUD.save(sessionId, appData, isNew);
}

function deleteApp(sessionId, appId) {
  return AppCRUD.delete(sessionId, appId);
}

function incrementViews(sessionId, appId) {
  return AppCRUD.incrementViews(sessionId, appId);
}

// ===================================================================
// 9. FAVORITES & RATINGS
// ===================================================================
const Social = {
  // Toggle favorite
  toggleFavorite(sessionId, appId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      if (user.id === 'GUEST') {
        return { success: false, error: 'Guest không thể lưu yêu thích trên server', isGuest: true };
      }

      const { headers, rows, sheet } = DB.getAll(CONFIG.SHEETS.FAVORITES);
      const userIdCol = headers.indexOf('UserID');
      const appIdCol = headers.indexOf('AppID');

      // Tìm favorite hiện tại
      for (let i = 0; i < rows.length; i++) {
        if (rows[i][userIdCol] === user.id && rows[i][appIdCol] === appId) {
          // Đã có → xóa
          sheet.deleteRow(i + 2);
          return { success: true, isFavorite: false, message: 'Đã bỏ yêu thích' };
        }
      }

      // Chưa có → thêm
      DB.appendRow(CONFIG.SHEETS.FAVORITES, [
        Utils.generateId('FAV'),
        user.id,
        appId,
        new Date().toISOString()
      ]);

      return { success: true, isFavorite: true, message: 'Đã thêm vào yêu thích' };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Đánh giá app
  rateApp(sessionId, appId, stars) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      if (user.id === 'GUEST') {
        return { success: false, error: 'Vui lòng đăng nhập để đánh giá' };
      }

      stars = parseInt(stars);
      if (isNaN(stars) || stars < 1 || stars > 5) {
        return { success: false, error: 'Số sao phải từ 1 đến 5' };
      }

      const { headers, rows, sheet } = DB.getAll(CONFIG.SHEETS.RATINGS);
      const userIdCol = headers.indexOf('UserID');
      const appIdCol = headers.indexOf('AppID');
      const starsCol = headers.indexOf('Stars');
      const updatedCol = headers.indexOf('UpdatedAt');
      const now = new Date().toISOString();

      // Tìm rating hiện tại
      for (let i = 0; i < rows.length; i++) {
        if (rows[i][userIdCol] === user.id && rows[i][appIdCol] === appId) {
          // Cập nhật
          sheet.getRange(i + 2, starsCol + 1).setValue(stars);
          sheet.getRange(i + 2, updatedCol + 1).setValue(now);
          
          const ratingData = DataAccess.calculateRating(appId);
          return {
            success: true,
            message: 'Đã cập nhật đánh giá',
            stars: stars,
            average: ratingData.average,
            count: ratingData.count
          };
        }
      }

      // Thêm mới
      DB.appendRow(CONFIG.SHEETS.RATINGS, [
        Utils.generateId('RAT'),
        appId,
        user.id,
        stars,
        now,
        now
      ]);

      DB.clearCache();
      const ratingData = DataAccess.calculateRating(appId);

      return {
        success: true,
        message: 'Đã đánh giá ' + stars + ' sao',
        stars: stars,
        average: ratingData.average,
        count: ratingData.count
      };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  }
};

function toggleFavorite(sessionId, appId) {
  return Social.toggleFavorite(sessionId, appId);
}

function rateApp(sessionId, appId, stars) {
  return Social.rateApp(sessionId, appId, stars);
}

// ===================================================================
// 10. COMMENTS
// ===================================================================
const Comments = {
  // Lấy comments theo app
  getByApp(sessionId, appId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const currentUser = sessionResult.user;
      const results = DB.findRows(CONFIG.SHEETS.COMMENTS, 'AppID', appId);
      
      // Lấy thông tin users
      const usersData = DB.getAll(CONFIG.SHEETS.USERS);
      const userMap = {};
      const userIdCol = usersData.headers.indexOf('UserID');
      const displayNameCol = usersData.headers.indexOf('DisplayName');
      
      usersData.rows.forEach(row => {
        userMap[row[userIdCol]] = row[displayNameCol] || row[userIdCol];
      });

      const comments = results
        .filter(r => r.data[r.headers.indexOf('Status')] !== 'Deleted')
        .map(r => {
          const getCol = (name) => r.headers.indexOf(name);
          const userId = r.data[getCol('UserID')];
          const content = Utils.safeJSONParse(r.data[getCol('Content')], { text: r.data[getCol('Content')] });

          return {
            id: r.data[getCol('CommentID')],
            appId: r.data[getCol('AppID')],
            userId: userId,
            userName: userMap[userId] || 'Người dùng',
            userInitial: (userMap[userId] || 'U').charAt(0).toUpperCase(),
            content: content.text || content.content || '',
            edited: content.edited || false,
            createdAt: r.data[getCol('CreatedAt')],
            canEdit: userId === currentUser.id || currentUser.role === ROLES.ADMIN,
            canDelete: userId === currentUser.id || currentUser.role === ROLES.ADMIN
          };
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      return { success: true, comments: comments };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Thêm comment
  add(sessionId, appId, content) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      const permissions = DataAccess.getUserPermissions(user);

      if (!permissions.canComment) {
        return { success: false, error: 'Không có quyền bình luận' };
      }

      if (!content || content.trim() === '') {
        return { success: false, error: 'Nội dung không được để trống' };
      }

      const trimmed = content.trim();
      if (trimmed.length > 1000) {
        return { success: false, error: 'Nội dung không được quá 1000 ký tự' };
      }

      const now = new Date().toISOString();
      const commentId = Utils.generateId('CMT');
      const contentJSON = JSON.stringify({ text: trimmed, edited: false });

      DB.appendRow(CONFIG.SHEETS.COMMENTS, [
        commentId,
        appId,
        user.id,
        contentJSON,
        now,
        now,
        null,
        'Active'
      ]);

      return {
        success: true,
        message: 'Đã thêm bình luận',
        comment: {
          id: commentId,
          appId: appId,
          userId: user.id,
          userName: user.displayName,
          userInitial: (user.displayName || 'U').charAt(0).toUpperCase(),
          content: trimmed,
          edited: false,
          createdAt: now,
          canEdit: true,
          canDelete: true
        }
      };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Cập nhật comment
  update(sessionId, commentId, newContent) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      const result = DB.findRow(CONFIG.SHEETS.COMMENTS, 'CommentID', commentId);

      if (!result) {
        return { success: false, error: 'Không tìm thấy bình luận' };
      }

      const userIdCol = result.headers.indexOf('UserID');
      if (result.data[userIdCol] !== user.id && user.role !== ROLES.ADMIN) {
        return { success: false, error: 'Không có quyền sửa bình luận này' };
      }

      if (!newContent || newContent.trim() === '') {
        return { success: false, error: 'Nội dung không được để trống' };
      }

      const trimmed = newContent.trim();
      const now = new Date().toISOString();
      const contentJSON = JSON.stringify({ text: trimmed, edited: true, editedAt: now });

      DB.updateRow(CONFIG.SHEETS.COMMENTS, result.index, {
        'Content': contentJSON,
        'UpdatedAt': now
      }, result.headers);

      return { success: true, message: 'Đã cập nhật', content: trimmed, edited: true };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  // Xóa comment (soft delete)
  delete(sessionId, commentId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const user = sessionResult.user;
      const result = DB.findRow(CONFIG.SHEETS.COMMENTS, 'CommentID', commentId);

      if (!result) {
        return { success: false, error: 'Không tìm thấy bình luận' };
      }

      const userIdCol = result.headers.indexOf('UserID');
      if (result.data[userIdCol] !== user.id && user.role !== ROLES.ADMIN) {
        return { success: false, error: 'Không có quyền xóa bình luận này' };
      }

      DB.updateRow(CONFIG.SHEETS.COMMENTS, result.index, {
        'Status': 'Deleted',
        'UpdatedAt': new Date().toISOString()
      }, result.headers);

      return { success: true, message: 'Đã xóa bình luận' };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  }
};

function getCommentsByApp(sessionId, appId) {
  return Comments.getByApp(sessionId, appId);
}

function addComment(sessionId, appId, content) {
  return Comments.add(sessionId, appId, content);
}

function updateComment(sessionId, commentId, newContent) {
  return Comments.update(sessionId, commentId, newContent);
}

function deleteComment(sessionId, commentId) {
  return Comments.delete(sessionId, commentId);
}

// ===================================================================
// 11. USER MANAGEMENT (Admin)
// ===================================================================
const UserManagement = {
  save(sessionId, userData, isNew) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const currentUser = sessionResult.user;
      if (currentUser.role !== ROLES.ADMIN) {
        return { success: false, error: 'Chỉ Admin mới có quyền' };
      }

      if (!userData.username || !/^[a-zA-Z0-9_]{3,20}$/.test(userData.username)) {
        return { success: false, error: 'Tên đăng nhập không hợp lệ (3-20 ký tự, chữ/số/gạch dưới)' };
      }

      if (isNew && (!userData.password || userData.password.length < 6)) {
        return { success: false, error: 'Mật khẩu phải có ít nhất 6 ký tự' };
      }

      // Kiểm tra trùng username
      const existing = DB.findRow(CONFIG.SHEETS.USERS, 'Username', userData.username.toLowerCase());
      if (existing && (isNew || existing.data[existing.headers.indexOf('UserID')] !== userData.id)) {
        return { success: false, error: 'Tên đăng nhập đã tồn tại' };
      }

      const now = new Date().toISOString();

      if (isNew) {
        const salt = Utils.generateSalt();
        const hash = Utils.hashPassword(userData.password, salt);
        const newId = Utils.generateId('USR');

        DB.appendRow(CONFIG.SHEETS.USERS, [
          newId,
          userData.username.toLowerCase(),
          hash,
          salt,
          userData.displayName || userData.username,
          userData.email || '',
          userData.role || ROLES.USER,
          'Active',
          now,
          '',
          0,
          ''
        ]);

        logActivity(currentUser.id, 'ADD_USER', 'Thêm user: ' + userData.username, 'Success');
        return { success: true, userId: newId, message: 'Đã thêm người dùng' };

      } else {
        const result = DB.findRow(CONFIG.SHEETS.USERS, 'UserID', userData.id);
        if (!result) {
          return { success: false, error: 'Không tìm thấy người dùng' };
        }

        const updates = {
          'DisplayName': userData.displayName || result.data[result.headers.indexOf('DisplayName')],
          'Email': userData.email || '',
          'Role': userData.role || result.data[result.headers.indexOf('Role')],
          'Status': userData.status || result.data[result.headers.indexOf('Status')]
        };

        // Đổi password nếu có
        if (userData.password && userData.password.length >= 6) {
          const salt = Utils.generateSalt();
          updates['PasswordHash'] = Utils.hashPassword(userData.password, salt);
          updates['Salt'] = salt;
        }

        DB.updateRow(CONFIG.SHEETS.USERS, result.index, updates, result.headers);
        logActivity(currentUser.id, 'UPDATE_USER', 'Cập nhật user: ' + userData.username, 'Success');
        return { success: true, message: 'Đã cập nhật người dùng' };
      }

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  delete(sessionId, userId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      const currentUser = sessionResult.user;
      if (currentUser.role !== ROLES.ADMIN) {
        return { success: false, error: 'Chỉ Admin mới có quyền' };
      }

      if (userId === currentUser.id) {
        return { success: false, error: 'Không thể tự xóa tài khoản' };
      }

      const result = DB.findRow(CONFIG.SHEETS.USERS, 'UserID', userId);
      if (!result) {
        return { success: false, error: 'Không tìm thấy người dùng' };
      }

      const username = result.data[result.headers.indexOf('Username')];
      DB.deleteRow(CONFIG.SHEETS.USERS, result.index);
      Auth.invalidateUserSessions(userId);

      logActivity(currentUser.id, 'DELETE_USER', 'Xóa user: ' + username, 'Success');
      return { success: true, message: 'Đã xóa người dùng' };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  }
};

function saveUser(sessionId, userData, isNew) {
  return UserManagement.save(sessionId, userData, isNew);
}

function deleteUser(sessionId, userId) {
  return UserManagement.delete(sessionId, userId);
}

// ===================================================================
// 12. CATEGORY MANAGEMENT
// ===================================================================
const CategoryManagement = {
  save(sessionId, catData, isNew) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      if (sessionResult.user.role !== ROLES.ADMIN) {
        return { success: false, error: 'Chỉ Admin mới có quyền' };
      }

      if (!catData.name || catData.name.trim() === '') {
        return { success: false, error: 'Tên danh mục không được để trống' };
      }

      // Kiểm tra trùng tên
      const { headers, rows } = DB.getAll(CONFIG.SHEETS.CATEGORIES);
      const nameCol = headers.indexOf('Name');
      const idCol = headers.indexOf('ID');

      for (let i = 0; i < rows.length; i++) {
        if (rows[i][nameCol].toLowerCase() === catData.name.toLowerCase()) {
          if (isNew || rows[i][idCol] !== catData.id) {
            return { success: false, error: 'Tên danh mục đã tồn tại' };
          }
        }
      }

      if (isNew) {
        const newId = Utils.generateId('CAT');
        DB.appendRow(CONFIG.SHEETS.CATEGORIES, [
          newId,
          catData.name.trim(),
          catData.icon || 'fa-folder',
          catData.description || '',
          parseInt(catData.sortOrder) || 0,
          'Active'
        ]);

        logActivity(sessionResult.user.id, 'ADD_CATEGORY', 'Thêm danh mục: ' + catData.name, 'Success');
        return { success: true, categoryId: newId, message: 'Đã thêm danh mục' };

      } else {
        const result = DB.findRow(CONFIG.SHEETS.CATEGORIES, 'ID', catData.id);
        if (!result) {
          return { success: false, error: 'Không tìm thấy danh mục' };
        }

        DB.updateRow(CONFIG.SHEETS.CATEGORIES, result.index, {
          'Name': catData.name.trim(),
          'Icon': catData.icon || 'fa-folder',
          'Description': catData.description || '',
          'SortOrder': parseInt(catData.sortOrder) || 0
        }, result.headers);

        logActivity(sessionResult.user.id, 'UPDATE_CATEGORY', 'Cập nhật: ' + catData.name, 'Success');
        return { success: true, message: 'Đã cập nhật danh mục' };
      }

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  },

  delete(sessionId, catId) {
    try {
      const sessionResult = Auth.validateSession(sessionId);
      if (!sessionResult.valid) {
        return { success: false, error: 'Phiên không hợp lệ' };
      }

      if (sessionResult.user.role !== ROLES.ADMIN) {
        return { success: false, error: 'Chỉ Admin mới có quyền' };
      }

      const result = DB.findRow(CONFIG.SHEETS.CATEGORIES, 'ID', catId);
      if (!result) {
        return { success: false, error: 'Không tìm thấy danh mục' };
      }

      const catName = result.data[result.headers.indexOf('Name')];
      DB.deleteRow(CONFIG.SHEETS.CATEGORIES, result.index);

      logActivity(sessionResult.user.id, 'DELETE_CATEGORY', 'Xóa: ' + catName, 'Success');
      return { success: true, message: 'Đã xóa danh mục' };

    } catch (e) {
      return { success: false, error: 'Lỗi: ' + e.message };
    }
  }
};

function saveCategory(sessionId, catData, isNew) {
  return CategoryManagement.save(sessionId, catData, isNew);
}

function deleteCategory(sessionId, catId) {
  return CategoryManagement.delete(sessionId, catId);
}

// ===================================================================
// 13. ADDITIONAL FUNCTIONS
// ===================================================================

// Upload ảnh
function uploadImage(sessionId, base64Data, fileName) {
  try {
    const sessionResult = Auth.validateSession(sessionId);
    if (!sessionResult.valid) {
      return { success: false, error: 'Phiên không hợp lệ' };
    }

    if (!base64Data || !base64Data.includes('base64,')) {
      return { success: false, error: 'Dữ liệu ảnh không hợp lệ' };
    }

    // Tìm hoặc tạo folder
    const folderName = '🌍iAppPro_Images';
    let folder;
    const folders = DriveApp.getFoldersByName(folderName);
    
    if (folders.hasNext()) {
      folder = folders.next();
    } else {
      folder = DriveApp.createFolder(folderName);
      folder.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    }

    // Tạo file
    const timestamp = Utilities.formatDate(new Date(), 'GMT+7', 'yyyyMMdd_HHmmss');
    const randomStr = Math.random().toString(36).substring(2, 8);
    const uniqueName = timestamp + '_' + randomStr + '.png';

    const base64Content = base64Data.split(',')[1];
    const decoded = Utilities.base64Decode(base64Content);
    const blob = Utilities.newBlob(decoded, 'image/png', uniqueName);

    const file = folder.createFile(blob);
    file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);

    const imageURL = 'https://drive.google.com/thumbnail?id=' + file.getId() + '&sz=w800';

    return { success: true, fileId: file.getId(), imageURL: imageURL };

  } catch (e) {
    return { success: false, error: 'Lỗi upload: ' + e.message };
  }
}

// Đổi mật khẩu
function changePassword(sessionId, currentPassword, newPassword) {
  try {
    const sessionResult = Auth.validateSession(sessionId);
    if (!sessionResult.valid) {
      return { success: false, error: 'Phiên không hợp lệ' };
    }

    const user = sessionResult.user;
    if (user.role === ROLES.GUEST) {
      return { success: false, error: 'Guest không thể đổi mật khẩu' };
    }

    if (!newPassword || newPassword.length < 6) {
      return { success: false, error: 'Mật khẩu mới phải có ít nhất 6 ký tự' };
    }

    const result = DB.findRow(CONFIG.SHEETS.USERS, 'UserID', user.id);
    if (!result) {
      return { success: false, error: 'Không tìm thấy người dùng' };
    }

    const saltCol = result.headers.indexOf('Salt');
    const hashCol = result.headers.indexOf('PasswordHash');
    
    const currentHash = Utils.hashPassword(currentPassword, result.data[saltCol]);
    if (currentHash !== result.data[hashCol]) {
      return { success: false, error: 'Mật khẩu hiện tại không đúng' };
    }

    const newSalt = Utils.generateSalt();
    const newHash = Utils.hashPassword(newPassword, newSalt);

    DB.updateRow(CONFIG.SHEETS.USERS, result.index, {
      'PasswordHash': newHash,
      'Salt': newSalt
    }, result.headers);

    logActivity(user.id, 'CHANGE_PASSWORD', 'Đổi mật khẩu thành công', 'Success');
    return { success: true, message: 'Đã đổi mật khẩu thành công' };

  } catch (e) {
    return { success: false, error: 'Lỗi: ' + e.message };
  }
}

// Gửi liên hệ
function submitContact(sessionId, contactData) {
  try {
    if (!contactData.name || !contactData.email || !contactData.message) {
      return { success: false, error: 'Vui lòng điền đầy đủ thông tin' };
    }

    DB.appendRow(CONFIG.SHEETS.CONTACTS, [
      Utils.generateId('CNT'),
      new Date().toISOString(),
      contactData.name,
      contactData.email,
      contactData.message,
      'Pending',
      '',
      ''
    ]);

    return { success: true, message: 'Đã gửi phản hồi thành công' };

  } catch (e) {
    return { success: false, error: 'Lỗi: ' + e.message };
  }
}

// Lấy contacts (Admin)
function getContacts(sessionId) {
  try {
    const sessionResult = Auth.validateSession(sessionId);
    if (!sessionResult.valid || sessionResult.user.role !== ROLES.ADMIN) {
      return { success: false, error: 'Không có quyền' };
    }

    const { headers, rows } = DB.getAll(CONFIG.SHEETS.CONTACTS);
    const getCol = (name) => headers.indexOf(name);

    const contacts = rows.map(row => ({
      id: row[getCol('ContactID')],
      timestamp: row[getCol('Timestamp')],
      name: row[getCol('Name')],
      email: row[getCol('Email')],
      message: row[getCol('Message')],
      status: row[getCol('Status')]
    })).reverse();

    return { success: true, contacts: contacts };

  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Lấy logs (Admin)
function getLogs(sessionId, limit) {
  try {
    const sessionResult = Auth.validateSession(sessionId);
    if (!sessionResult.valid || sessionResult.user.role !== ROLES.ADMIN) {
      return { success: false, error: 'Không có quyền' };
    }

    const { headers, rows } = DB.getAll(CONFIG.SHEETS.LOGS);
    const getCol = (name) => headers.indexOf(name);

    const logs = rows.slice(-(limit || 100)).reverse().map(row => ({
      id: row[getCol('LogID')],
      timestamp: row[getCol('Timestamp')],
      userId: row[getCol('UserID')],
      action: row[getCol('Action')],
      details: row[getCol('Details')],
      result: row[getCol('Result')]
    }));

    return { success: true, logs: logs };

  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Khởi tạo hệ thống
function initializeSystem() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    
    const sheetsConfig = {
      [CONFIG.SHEETS.APPS]: ['ID', 'Name', 'Link', 'Description', 'Category', 'ImageURL', 'Visibility', 'CreatedBy', 'CreatedAt', 'UpdatedAt', 'Views', 'Status', 'VideoURL', 'Tags'],
      [CONFIG.SHEETS.USERS]: ['UserID', 'Username', 'PasswordHash', 'Salt', 'DisplayName', 'Email', 'Role', 'Status', 'CreatedAt', 'LastLogin', 'FailedAttempts', 'LockedUntil'],
      [CONFIG.SHEETS.SESSIONS]: ['SessionID', 'UserID', 'CreatedAt', 'ExpiresAt', 'IPAddress', 'UserAgent', 'IsValid'],
      [CONFIG.SHEETS.CATEGORIES]: ['ID', 'Name', 'Icon', 'Description', 'SortOrder', 'Status'],
      [CONFIG.SHEETS.COMMENTS]: ['CommentID', 'AppID', 'UserID', 'Content', 'CreatedAt', 'UpdatedAt', 'ParentID', 'Status'],
      [CONFIG.SHEETS.FAVORITES]: ['FavoriteID', 'UserID', 'AppID', 'CreatedAt'],
      [CONFIG.SHEETS.RATINGS]: ['RatingID', 'AppID', 'UserID', 'Stars', 'CreatedAt', 'UpdatedAt'],
      [CONFIG.SHEETS.LOGS]: ['LogID', 'Timestamp', 'UserID', 'Action', 'Details', 'Result', 'IPAddress'],
      [CONFIG.SHEETS.CONTACTS]: ['ContactID', 'Timestamp', 'Name', 'Email', 'Message', 'Status', 'HandledBy', 'HandledAt'],
      [CONFIG.SHEETS.NOTIFICATIONS]: ['NotifID', 'UserID', 'Type', 'Title', 'Content', 'IsRead', 'CreatedAt', 'Link'],
      [CONFIG.SHEETS.PERMISSIONS]: ['PermID', 'AppID', 'TargetType', 'TargetID', 'CanView', 'CanAdd', 'CanEdit', 'CanDelete', 'CanComment']
    };

    for (const [sheetName, headers] of Object.entries(sheetsConfig)) {
      let sheet = ss.getSheetByName(sheetName);
      if (!sheet) {
        sheet = ss.insertSheet(sheetName);
        sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
        sheet.getRange(1, 1, 1, headers.length)
          .setFontWeight('bold')
          .setBackground('#4285f4')
          .setFontColor('#ffffff');
        sheet.setFrozenRows(1);
      }
    }

    // Tạo admin mặc định nếu chưa có
    const usersSheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    const users = usersSheet.getDataRange().getValues();
    
    if (users.length <= 1) {
      const salt = Utils.generateSalt();
      const hash = Utils.hashPassword(CONFIG.DEFAULT_ADMIN.password, salt);
      
      usersSheet.appendRow([
        Utils.generateId('USR'),
        CONFIG.DEFAULT_ADMIN.username,
        hash,
        salt,
        CONFIG.DEFAULT_ADMIN.displayName,
        '',
        ROLES.ADMIN,
        'Active',
        new Date().toISOString(),
        '',
        0,
        ''
      ]);
    }

    return { success: true, message: 'Hệ thống đã được khởi tạo thành công (V5.0)' };

  } catch (e) {
    Logger.log('InitializeSystem error: ' + e.message);
    return { success: false, error: e.message };
  }
}

// ===================================================================
// DEBUG & FIX FUNCTIONS
// ===================================================================

/**
 * Kiểm tra và tạo admin - CHẠY HÀM NÀY
 */
function fixAdminAccount() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    
    // Kiểm tra sheet DB_Users
    let usersSheet = ss.getSheetByName('DB_Users');
    
    if (!usersSheet) {
      // Tạo sheet mới
      usersSheet = ss.insertSheet('DB_Users');
      usersSheet.getRange(1, 1, 1, 12).setValues([[
        'UserID', 'Username', 'PasswordHash', 'Salt', 'DisplayName', 
        'Email', 'Role', 'Status', 'CreatedAt', 'LastLogin', 
        'FailedAttempts', 'LockedUntil'
      ]]);
      usersSheet.getRange(1, 1, 1, 12)
        .setFontWeight('bold')
        .setBackground('#4285f4')
        .setFontColor('#ffffff');
      usersSheet.setFrozenRows(1);
      Logger.log('✅ Đã tạo sheet DB_Users');
    }
    
    // Kiểm tra có admin chưa
    const data = usersSheet.getDataRange().getValues();
    let hasAdmin = false;
    
    for (let i = 1; i < data.length; i++) {
      if (data[i][1] === 'admin') {
        hasAdmin = true;
        Logger.log('✅ Đã có tài khoản admin ở dòng ' + (i + 1));
        
        // Reset password cho admin
        const salt = generateSaltForFix();
        const hash = hashPasswordForFix('Admin@123', salt);
        
        usersSheet.getRange(i + 1, 3).setValue(hash);  // PasswordHash
        usersSheet.getRange(i + 1, 4).setValue(salt);  // Salt
        usersSheet.getRange(i + 1, 8).setValue('Active'); // Status
        usersSheet.getRange(i + 1, 11).setValue(0);    // FailedAttempts
        usersSheet.getRange(i + 1, 12).setValue('');   // LockedUntil
        
        Logger.log('✅ Đã reset mật khẩu admin thành: Admin@123');
        break;
      }
    }
    
    if (!hasAdmin) {
      // Tạo admin mới
      const salt = generateSaltForFix();
      const hash = hashPasswordForFix('Admin@123', salt);
      const userId = 'USR_' + Date.now();
      
      usersSheet.appendRow([
        userId,
        'admin',
        hash,
        salt,
        'Administrator',
        'admin@example.com',
        'Admin',
        'Active',
        new Date().toISOString(),
        '',
        0,
        ''
      ]);
      
      Logger.log('✅ Đã tạo tài khoản admin mới');
      Logger.log('   - Username: admin');
      Logger.log('   - Password: Admin@123');
      Logger.log('   - UserID: ' + userId);
    }
    
    // Kiểm tra các sheet khác
    initializeAllSheets();
    
    return {
      success: true,
      message: 'Đã sửa tài khoản admin. Username: admin, Password: Admin@123'
    };
    
  } catch (e) {
    Logger.log('❌ Lỗi: ' + e.message);
    return { success: false, error: e.message };
  }
}

function generateSaltForFix() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let salt = '';
  for (let i = 0; i < 32; i++) {
    salt += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return salt;
}

function hashPasswordForFix(password, salt) {
  const combined = salt + password + salt;
  const hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, combined);
  return hash.map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
}

function initializeAllSheets() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  
  const sheetsConfig = {
    'DB_Apps': ['ID', 'Name', 'Link', 'Description', 'Category', 'ImageURL', 'Visibility', 'CreatedBy', 'CreatedAt', 'UpdatedAt', 'Views', 'Status', 'VideoURL', 'Tags'],
    'DB_Sessions': ['SessionID', 'UserID', 'CreatedAt', 'ExpiresAt', 'IPAddress', 'UserAgent', 'IsValid'],
    'DB_Categories': ['ID', 'Name', 'Icon', 'Description', 'SortOrder', 'Status'],
    'DB_Comments': ['CommentID', 'AppID', 'UserID', 'Content', 'CreatedAt', 'UpdatedAt', 'ParentID', 'Status'],
    'DB_Favorites': ['FavoriteID', 'UserID', 'AppID', 'CreatedAt'],
    'DB_Ratings': ['RatingID', 'AppID', 'UserID', 'Stars', 'CreatedAt', 'UpdatedAt'],
    'DB_Logs': ['LogID', 'Timestamp', 'UserID', 'Action', 'Details', 'Result', 'IPAddress'],
    'DB_Contacts': ['ContactID', 'Timestamp', 'Name', 'Email', 'Message', 'Status', 'HandledBy', 'HandledAt'],
    'DB_Notifications': ['NotifID', 'UserID', 'Type', 'Title', 'Content', 'IsRead', 'CreatedAt', 'Link'],
    'DB_AppPermissions': ['PermID', 'AppID', 'TargetType', 'TargetID', 'CanView', 'CanAdd', 'CanEdit', 'CanDelete', 'CanComment']
  };
  
  for (const [sheetName, headers] of Object.entries(sheetsConfig)) {
    let sheet = ss.getSheetByName(sheetName);
    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
      sheet.getRange(1, 1, 1, headers.length)
        .setFontWeight('bold')
        .setBackground('#4285f4')
        .setFontColor('#ffffff');
      sheet.setFrozenRows(1);
      Logger.log('✅ Đã tạo sheet: ' + sheetName);
    }
  }
  
  // Tạo một số danh mục mặc định
  const catSheet = ss.getSheetByName('DB_Categories');
  const catData = catSheet.getDataRange().getValues();
  
  if (catData.length <= 1) {
    const defaultCats = [
      ['CAT_1', 'Công cụ', 'fa-tools', 'Các công cụ hỗ trợ công việc', 1, 'Active'],
      ['CAT_2', 'Báo cáo', 'fa-chart-bar', 'Báo cáo và thống kê', 2, 'Active'],
      ['CAT_3', 'Nhân sự', 'fa-users', 'Quản lý nhân sự', 3, 'Active'],
      ['CAT_4', 'Tài chính', 'fa-money-bill-wave', 'Quản lý tài chính', 4, 'Active'],
      ['CAT_5', 'Khác', 'fa-folder', 'Danh mục khác', 99, 'Active']
    ];
    
    defaultCats.forEach(cat => catSheet.appendRow(cat));
    Logger.log('✅ Đã tạo danh mục mặc định');
  }
}

/**
 * Xem thông tin admin hiện tại
 */
function checkAdminInfo() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const usersSheet = ss.getSheetByName('DB_Users');
  
  if (!usersSheet) {
    Logger.log('❌ Không có sheet DB_Users');
    return;
  }
  
  const data = usersSheet.getDataRange().getValues();
  Logger.log('📊 Tổng số dòng: ' + data.length);
  Logger.log('📊 Headers: ' + data[0].join(', '));
  
  for (let i = 1; i < data.length; i++) {
    Logger.log('---');
    Logger.log('Dòng ' + (i + 1) + ':');
    Logger.log('  UserID: ' + data[i][0]);
    Logger.log('  Username: ' + data[i][1]);
    Logger.log('  Role: ' + data[i][6]);
    Logger.log('  Status: ' + data[i][7]);
    Logger.log('  FailedAttempts: ' + data[i][10]);
    Logger.log('  LockedUntil: ' + data[i][11]);
  }
}

/**
 * Test đăng nhập
 */
function testLogin() {
  const result = login('admin', 'Admin@123');
  Logger.log('🔐 Kết quả đăng nhập:');
  Logger.log(JSON.stringify(result, null, 2));
  return result;
}



// ===================================================================
// END OF CODE.GS - iAPP PRO V5.0
// ===================================================================

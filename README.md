# 🗂️ frankenfs - Safe, Reliable File Systems for Linux

[![Download frankenfs](https://img.shields.io/badge/Download-frankenfs-blue?style=for-the-badge)](https://github.com/buitranxuanhuy/frankenfs/releases)

---

## 📖 What is frankenfs?

frankenfs is a tool that helps your Linux computer work with files safely and efficiently. It recreates popular file systems called ext4 and btrfs using a programming language called Rust. This tool focuses on keeping your data safe, making sure your files stay organized, and healing itself if something goes wrong.

The software works by sitting between your computer’s hard drive and the programs you use. This setup is called FUSE (Filesystem in Userspace). It means frankenfs acts like a translator for your storage, so your Linux system can read and write files without risk.

---

## 💻 Who is this for?

frankenfs is made for people using Linux who want a safer and smarter way to manage their file systems. You don’t need to know how to code or understand complex computer systems to use it. Whether you are a casual user or someone who stores important data, frankenfs offers a reliable solution to protect and recover your files.

---

## 🛠️ Key Features

- **Memory-safe:** frankenfs avoids common bugs that cause crashes or data loss, keeping your files safe.
- **Supports ext4 and btrfs:** Two of the most popular file system types on Linux.
- **Self-healing:** Uses smart technology to fix minor data problems automatically.
- **Block-level MVCC:** Helps manage changes to your files cleanly without data corruption.
- **Rust-based:** Made without unsafe code, which improves security and stability.
- **Works on Linux:** Designed specifically for Linux operating systems with FUSE support.

---

## 🖥️ System Requirements

Before installing, make sure your computer meets these requirements:

- **Operating System:** Linux (Ubuntu, Fedora, Debian, or similar)
- **Kernel Version:** 4.15 or higher (for FUSE support)
- **Disk Space:** At least 200 MB free disk space for installation and running frankenfs
- **Memory:** Minimum 2 GB RAM, recommended 4 GB or more
- **FUSE:** FUSE (Filesystem in Userspace) must be installed. Most Linux distributions include it by default. If not, you will need to install it first.

---

## 🚀 Getting Started

This section guides you step-by-step on how to download, install, and run frankenfs on your Linux computer.

---

## ⬇️ Download & Install

You can find frankenfs ready to use on its release page. Visit this page to download the version that fits your system:

[Download frankenfs Releases](https://github.com/buitranxuanhuy/frankenfs/releases)

### How to download:

1. Click the link above to visit the releases page.
2. Choose the latest version.
3. Select the package that matches your Linux distribution (usually a `.tar.gz` file or similar).
4. Download the file to your computer.

### How to install:

1. Open a Terminal window.
2. Navigate to the folder where you saved the file. For example:
   ```
   cd ~/Downloads
   ```
3. Extract the downloaded file by typing:
   ```
   tar -xvzf frankenfs-x.y.z.tar.gz
   ```
   Replace `x.y.z` with the version number you downloaded.
4. Change into the extracted folder:
   ```
   cd frankenfs-x.y.z
   ```
5. Run the installation script:
   ```
   sudo ./install.sh
   ```
   This command asks for your password to allow system changes.

---

## ▶️ Running frankenfs

After installation, you can start frankenfs on your system.

1. **Create a mount point:** This is where your file system will appear.
   ```
   mkdir ~/mnt/frankenfs
   ```
2. **Start frankenfs:** Replace `/dev/sdX` with the disk or partition you want to use.
   ```
   frankenfs /dev/sdX ~/mnt/frankenfs
   ```
3. Your files should now be accessible at `~/mnt/frankenfs`.
4. To stop frankenfs and unmount:
   ```
   fusermount -u ~/mnt/frankenfs
   ```

---

## 🔧 Configuration Tips

- To ensure frankenfs starts with the right settings, you can create a configuration file in your home folder named `.frankenfs.conf`.
- Example settings include:
  ```
  filesystem=ext4
  mount_options=defaults
  enable_self_healing=true
  ```
- The default settings work for most users.

---

## 💡 Common Questions

**Q: Do I need to know Linux commands to use frankenfs?**  
A: Basic Linux commands help, but you don’t need to be an expert. The instructions here guide you through the basic steps.

**Q: Can frankenfs work with my existing files?**  
A: Yes. It is designed to support ext4 and btrfs file systems, which are commonly used on Linux.

**Q: What happens if frankenfs detects an error?**  
A: It uses built-in self-healing to fix small problems automatically. For bigger issues, it will alert you.

---

## 📂 File System Support Details

- **ext4:** The reliable default file system on many Linux distros. frankenfs reimplements ext4 to enhance safety using Rust.
- **btrfs:** A newer, advanced file system known for features like snapshots and checksums. frankenfs safely supports btrfs with added repair features.

---

## ⚙️ How frankenfs Keeps Your Data Safe

frankenfs uses modern programming techniques to avoid common causes of crashes or data loss. Memory safety means it prevents many errors that could damage files. Multi-Version Concurrency Control (MVCC) helps manage changes to files in a way that keeps the data consistent, even when accessed by multiple programs.

The self-healing feature uses a method called RaptorQ to recover parts of files that might be damaged, without losing the entire file.

---

## 📚 Learn More

If you want to explore how frankenfs works under the hood or help with development, visit the [frankenfs GitHub repository](https://github.com/buitranxuanhuy/frankenfs).

---

[Download frankenfs Releases](https://github.com/buitranxuanhuy/frankenfs/releases)
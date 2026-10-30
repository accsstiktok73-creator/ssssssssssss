"""Run: python import-videos.py path/to/SORA-With-Videos(3).zip"""
import pathlib,sys,zipfile,shutil,os
root=pathlib.Path(os.environ.get('DATA_DIR',str(pathlib.Path(__file__).resolve().parent/'data')))/'private-videos';root.mkdir(exist_ok=True)
count=0
with zipfile.ZipFile(sys.argv[1]) as z:
 for i in z.infolist():
  p=pathlib.PurePosixPath(i.filename)
  if p.suffix.lower() in ('.mp4','.webm','.mov') and p.parent.name in ('videogifts','video qua','video quà'):
   with z.open(i) as src,(root/p.name).open('wb') as dst:shutil.copyfileobj(src,dst)
   count+=1
print('Imported',count,'videos. Keep these on your server only.')

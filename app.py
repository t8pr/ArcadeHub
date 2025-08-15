from flask import Flask, render_template
import supabase

app = Flask(__name__)

# Initialize Supabase client (replace with your credentials)
supabase_url = "https://your-project.supabase.co"
supabase_key = "your-supabase-key"
supabase_client = supabase.create_client(supabase_url, supabase_key)

GAMES = [
    {
        "slug": "abandoned-riyadh",
        "title": "مهجول الرياض",
        "developer": "استوديو الأفق",
        "developer_account": "@AlUfuqStudio",
        "description": "لعبة رعب بقصص عربية حيث تستكشف مباني الرياض المهجورة وتكشف أسرارها المظلمة. انتبه للأصوات الغريبة ولا تدع الظلام يلحق بك!",
        "price": 49.99,
        "rating": 4.7,
        "downloads": "1,245",
        "release_date": "15 يناير 2023",
        "size": "2.4 جيجابايت",
        "version": "1.2.0",
        "video_url": "https://www.youtube.com/embed/v35NNDsBehQ",
        "images": [
            "https://mir-s3-cdn-cf.behance.net/projects/404/227867169167761.Y3JvcCw0MzE0LDMzNzUsMTY3Niww.png",
            "https://pbs.twimg.com/media/ERzWOxUW4AAfImu.png",
        ],
        "thumbnail": "https://play-lh.googleusercontent.com/N4xrvxasKOCSVU_ZTrSGLEqFEX_6n5MaNUbzD2Tl3giTPJUa9pMyjeasHIXAeGtv9A"
    },
    {
        "slug": "desert-rally",
        "title": "سباق الصحراء",
        "developer": "ألعاب الخليج",
        "developer_account": "@GulfGames",
        "description": "سباق سيارات سريع في صحراء الربع الخالي مع تحديات وعواصف رملية ومطاردة الشرطة. اختر سيارتك وكن الأسرع!",
        "price": 29.99,
        "rating": 4.3,
        "downloads": "3,542",
        "release_date": "5 مارس 2023",
        "size": "1.8 جيجابايت",
        "version": "1.5.2",
        "video_url": "https://www.youtube.com/embed/mEiXt2C8_V4?si=o7ic4sS7HxlOJ4Pt",
        "images": [
            "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTLUTnLzsxItzyH25RVqFcRNSWUlROGC5Gc6w&s",
        ],
        "thumbnail": "https://images.stockcake.com/public/2/e/9/2e9185c6-70e5-4d16-9e0a-c616ffcba528_medium/pixelated-rally-action-stockcake.jpg"
    },
    {
        "slug": "arabian-nights",
        "title": "ليالي عربية",
        "developer": "استوديو ألف ليلة",
        "developer_account": "@1001NightsDev",
        "description": "مغامرة غامضة في عالم ألف ليلة وليلة حيث تحل الألغاز وتقاتل المخلوقات الأسطورية وتكتشف كنوزًا قديمة.",
        "price": 39.99,
        "rating": 4.8,
        "downloads": "2,876",
        "release_date": "22 نوفمبر 2022",
        "size": "3.1 جيجابايت",
        "version": "2.0.1",
        "video_url": "https://www.youtube.com/embed/7B7Y8VLvW8E",
        "images": [
            "https://i.pinimg.com/originals/8a/1b/6d/8a1b6d8e3c7b8e3a3e3b3e3e3e3e3e3e.jpg",
            "https://i.pinimg.com/originals/8a/1b/6d/8a1b6d8e3c7b8e3a3e3b3e3e3e3e3e3e.jpg"
        ],
        "thumbnail": "https://i.pinimg.com/originals/8a/1b/6d/8a1b6d8e3c7b8e3a3e3b3e3e3e3e3e3e.jpg"
    },
    {
        "slug": "mecca-pilgrim",
        "title": "حاج مكة",
        "developer": "ألعاب إسلامية",
        "developer_account": "@IslamicGames",
        "description": "محاكاة واقعية لرحلة الحج من بدايتها حتى نهايتها مع تفاعل كامل مع البيئة والمشاعر والأدعية.",
        "price": 0.00,
        "rating": 4.9,
        "downloads": "15,342",
        "release_date": "1 ذو الحجة 1443",
        "size": "1.2 جيجابايت",
        "version": "1.0.0",
        "video_url": "https://www.youtube.com/embed/5BZ3sO7cdz4",
        "images": [
            "https://www.islamic-relief.org/wp-content/uploads/2020/07/Hajj-2020.jpg",
            "https://www.islamic-relief.org/wp-content/uploads/2020/07/Hajj-2020-2.jpg"
        ],
        "thumbnail": "https://www.islamic-relief.org/wp-content/uploads/2020/07/Hajj-2020.jpg"
    },
    {
        "slug": "bedouin-survival",
        "title": "بقاء البدو",
        "developer": "ألعاب الصحراء",
        "developer_account": "@DesertSurvival",
        "description": "لعبة بقاء في الصحراء العربية حيث يجب عليك إيجاد الماء والطعام وبناء مأوى والدفاع عن نفسك من الحيوانات المفترسة.",
        "price": 19.99,
        "rating": 4.2,
        "downloads": "4,231",
        "release_date": "10 يونيو 2023",
        "size": "2.7 جيجابايت",
        "version": "1.3.4",
        "video_url": "https://www.youtube.com/embed/9zG_DlxykDk",
        "images": [
            "https://i.ytimg.com/vi/9zG_DlxykDk/maxresdefault.jpg",
            "https://i.ytimg.com/vi/9zG_DlxykDk/hqdefault.jpg"
        ],
        "thumbnail": "https://i.ytimg.com/vi/9zG_DlxykDk/maxresdefault.jpg"
    },
    {
        "slug": "arabic-chef",
        "title": "الشيف العربي",
        "developer": "ألعاب الطهي",
        "developer_account": "@ArabicCooking",
        "description": "اصبح شيفًا محترفًا وتعلم طبخ أشهر الأكلات العربية من المقلوبة إلى الكبسة إلى الحلويات الشرقية.",
        "price": 14.99,
        "rating": 4.0,
        "downloads": "7,654",
        "release_date": "5 مايو 2023",
        "size": "1.5 جيجابايت",
        "version": "1.1.2",
        "video_url": "https://www.youtube.com/embed/3jZ5q3q3q3q",
        "images": [
            "https://www.chefspencil.com/wp-content/uploads/Arabic-Food.jpg",
            "https://www.chefspencil.com/wp-content/uploads/Arabic-Food-2.jpg"
        ],
        "thumbnail": "https://www.chefspencil.com/wp-content/uploads/Arabic-Food.jpg"
    },
    {
        "slug": "dubai-simulator",
        "title": "محاكي دبي",
        "developer": "ألعاب الإمارات",
        "developer_account": "@UAE_Games",
        "description": "عش حياة الرفاهية في دبي حيث يمكنك قيادة السيارات الفاخرة والطيران بالمروحيات والتنقل بين ناطحات السحاب.",
        "price": 59.99,
        "rating": 4.5,
        "downloads": "9,876",
        "release_date": "2 ديسمبر 2023",
        "size": "4.2 جيجابايت",
        "version": "1.7.0",
        "video_url": "https://www.youtube.com/embed/4jZ5q3q3q3q",
        "images": [
            "https://www.visitdubai.com/-/media/gathercontent/department/things-to-do/attractions/listing-image/burj-khalifa-1.jpg",
            "https://www.visitdubai.com/-/media/gathercontent/department/things-to-do/attractions/listing-image/burj-khalifa-2.jpg"
        ],
        "thumbnail": "https://www.visitdubai.com/-/media/gathercontent/department/things-to-do/attractions/listing-image/burj-khalifa-1.jpg"
    }
]

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

@app.route('/games')
def games():
    return render_template('games.html', games=GAMES)

@app.route('/games/<game_slug>')
def game_details(game_slug):
    game = next((g for g in GAMES if g['slug'] == game_slug), None)
    if not game:
        return "Game not found", 404
    
    # Sanitize YouTube URL
    if 'youtube.com' in game['video_url']:
        game['safe_video_url'] = game['video_url'].replace('watch?v=', 'embed/')
    else:
        game['safe_video_url'] = game['video_url']
    
    return render_template('game_details.html', game=game)
if __name__ == '__main__':
    app.run(debug=True)